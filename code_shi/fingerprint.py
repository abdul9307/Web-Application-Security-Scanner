import requests
from urllib.parse import urlsplit, urljoin, urlparse
import ssl
import socket
import dns.resolver
import os
import re
from bs4 import BeautifulSoup
import concurrent.futures


def setup_file(url):
    # Creates the output folder and returns the file path
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    domain = urlsplit(url).hostname
    if domain.startswith('www.'):
        domain = domain[4:]

    # Create folder if it doesn't exist
    os.makedirs("Fingerprinting_Results", exist_ok=True)
    # Define file path
    file_path = f"Fingerprinting_Results/Fingerprint_{domain}.txt"
    # Add a header to the file for this scan session
    with open(file_path, 'a') as f:
        f.write(f"\n{'='*50}\n--- New Scan Started for {domain} ---\n{'='*50}\n")
    return file_path


def log(msg, output_file):
    with open(output_file, 'a') as f:
        f.write(msg + '\n')

def check_headers(url, output_file):
    print("Checking HTTP headers for security and tech stack information...", output_file)
    headers_to_check = [
                        # Server: Web Server and Version, Date: Date and Time, Via: Proxy servers, gateways
                        "Server", "Date", "Via",

                        # Tech Stack & Cookies
                        "X-Powered-By", "X-Cache", "Set-Cookie", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator",

                        # Cloud/CDN specifics
                        "CF-Ray", "X-Amz-Cf-Id",

                        # Security & CORS
                        "Strict-Transport-Security", "Content-Security-Policy", 
                        "X-Frame-Options", "X-Content-Type-Options", "Access-Control-Allow-Origin"
                        ]
    
    try:
        response = requests.head(url, timeout=5)
        for header in headers_to_check:
            if header in response.headers:
                log(f"{header}: {response.headers[header]}", output_file)
    except requests.RequestException as e:
        log(f"Error connecting to target: {e}", output_file)
    print("HTTP header check completed. Results saved to:", output_file)


def check_certificates(url, output_file):
    print("Checking SSL/TLS certificates for validity and issuer information...", output_file)
    # Checks SSL certificate
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    hostname = urlsplit(url).hostname
    # 443,8443, 4433: HTTPS, 993: IMAP, 80: HTTP
    ports = [443, 8443, 4433, 993, 80]

    # Creates an SSL context object: default secure settings with certificate validation
    context = ssl.create_default_context()
    for port in ports:
        log(f"\n[*] Testing {hostname} on port {port}...", output_file)
    
        try:
            # Opens a standard TCP connection to target port
            with socket.create_connection((hostname, port), timeout=3) as sock:
                # Wraps TCP connection in SSL context
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # returns SSL certificate
                    cert = ssock.getpeercert()
                    log("  [+] SSL Certificate found!", output_file)
                    print("  [+] SSL Certificate found!")
                    # Issuer: Certificate Authority (CA)
                    log("  Issuer:" + str(cert.get("issuer")), output_file)
                    log("  Subject:" + str(cert.get("subject")), output_file)
                    
        except ConnectionRefusedError:
            log("  [-] Port is closed (Connection refused).", output_file)
        except socket.timeout:
            log("  [-] Connection timed out (Port likely filtered by a firewall).", output_file)
        except ssl.SSLError:
            log("  [-] Port is open, but it is not running a standard SSL/TLS service.", output_file)
        except Exception as e:
            log(f"  [-] Unexpected error: {e}", output_file)
        print(f"SSL/TLS check completed for port {port}. Results saved to: {output_file}")


def check_default_files(url, output_file):
    print("Checking for default files like robots.txt, sitemap.xml, and security.txt...")
    # Ensure the base URL doesn't end with a slash so we don't get double slashes
    base_url = url.rstrip('/')
    files_to_check = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/humans.txt"]
    
    log(f"\n[*] Checking for default files on {base_url}...", output_file)
    for file in files_to_check:
        target_url = base_url + file
        try:
            # We use GET here instead of HEAD because sometimes servers return 200 
            # for a HEAD request even if the file is just a custom 404 page.
            response = requests.get(target_url, timeout=5)
            if response.status_code == 200:
                log(f"  [+] Found: {target_url}", output_file)
            else:
                log(f"  [-] Not Found (Status {response.status_code}): {file}", output_file)
        except requests.RequestException as e:
            log(f"  [-] Error checking {file}: {e}", output_file)
        print(f"Default file check completed for {file}. Results saved to: {output_file}")

def check_dns_records(url, output_file):
    print("Checking DNS records for A, MX, and TXT entries...")
    # Parse the domain out of the URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    domain = urlsplit(url).hostname
    # Remove 'www.' if present, as DNS records are usually on the root domain
    if domain.startswith('www.'):
        domain = domain[4:]
        
    log(f"\n[*] Checking DNS Records for {domain}...", output_file)
    # A: IP4 addresses, MX: Mail exchange records, TXT: Text records
    record_types = ['A', 'MX', 'TXT']
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            log(f"\n  [+] {record} Records Found:", output_file)
            for rdata in answers:
                log(f"      - {rdata.to_text()}", output_file)
        except dns.resolver.NoAnswer:
            log(f"\n  [-] No {record} records found.", output_file)
        except dns.resolver.NXDOMAIN:
            log(f"\n  [-] Domain {domain} does not exist.", output_file)
            break # If the domain doesn't exist, stop checking other records
        except Exception as e:
            log(f"\n  [-] Error retrieving {record} records: {e}", output_file)
        print(f"DNS record check completed for {record}. Results saved to: {output_file}")

def check_http_methods(url, output_file):
    print("Checking allowed HTTP methods for potential security risks...")
    log(f"\n[*] Checking allowed HTTP methods for {url}...", output_file)
    try:
        # Using requests.options() specifically
        response = requests.options(url, timeout=5)
        if 'Allow' in response.headers:
            methods = response.headers['Allow']
            log(f"  [+] Allowed Methods: {methods}", output_file)
            # Highlight potentially dangerous methods
            if any(m in methods for m in ['PUT', 'DELETE', 'TRACE']):
                log("  [!] WARNING: Potentially dangerous methods enabled!", output_file)
        else:
            log("  [-] No 'Allow' header returned by the server.", output_file)
            
    except requests.RequestException as e:
        log(f"  [-] Error checking methods: {e}", output_file)
    print(f"HTTP methods check completed. Results saved to: {output_file}")

def check_waf(url, output_file):
    print("Checking for Web Application Firewall (WAF) presence...")
    base_url = url.rstrip('/')
    # A standard payload that WAFs are hardcoded to block
    malicious_url = base_url + "/?id=<script>alert('WAF_TEST')</script>"

    log(f"\n[*] Testing for Web Application Firewall (WAF) presence...", output_file)
    try:
        # Check normal baseline first
        normal_resp = requests.get(base_url, timeout=5)
        # Check malicious request
        malicious_resp = requests.get(malicious_url, timeout=5)
        if normal_resp.status_code == 200 and malicious_resp.status_code in [403, 406, 501]:
            log(f"  [+] WAF DETECTED! Request blocked with status {malicious_resp.status_code}", output_file)
            # WAFs often leave their name in the server header when they block a request
            if 'Server' in malicious_resp.headers:
                log(f"      WAF Signature/Server: {malicious_resp.headers['Server']}", output_file)
        else:
            log("  [-] No obvious WAF detected (payload was not blocked).", output_file)
            
    except requests.RequestException as e:
        log(f"  [-] Error during WAF test: {e}", output_file)
    print(f"WAF check completed. Results saved to: {output_file}")

    
def enumerate_subdomains(url, output_file):
    print("Enumerating subdomains using crt.sh...")
    domain = urlsplit(url).hostname
    if domain.startswith('www.'):
        domain = domain[4:]
        
    log(f"\n[*] Querying crt.sh for subdomains of {domain} (this may take a moment)...", output_file)
    try:
        # The crt.sh API returns JSON data
        crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(crt_url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            subdomains = set() # Use a set to automatically remove duplicates
            
            for entry in data:
                name = entry['name_value']
                # Sometimes crt.sh returns wildcard domains (*.example.com) or multiple domains separated by newlines
                for sub in name.split('\n'):
                    if not sub.startswith('*'):
                        subdomains.add(sub.strip())
            
            if subdomains:
                log(f"  [+] Found {len(subdomains)} subdomains:", output_file)
                for sub in sorted(subdomains):
                    log(f"      - {sub}", output_file)
            else:
                log("  [-] No subdomains found in CT logs.", output_file)
        else:
            log(f"  [-] crt.sh returned status {response.status_code}", output_file)
            
    except Exception as e:
        log(f"  [-] Error enumerating subdomains: {e}", output_file)
    print(f"Subdomain enumeration completed. Results saved to: {output_file}")

def check_html_generator(url, output_file):
    print(f"Checking HTML source for CMS/Generator tags on {url}...")
    log(f"\n[*] Checking HTML source for CMS/Generator tags...", output_file)
    try:
        response = requests.get(url, timeout=5)
        html_content = response.text
        
        # Use a regular expression to find <meta name="generator" content="...">
        match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
        
        if match:
            generator = match.group(1)
            log(f"  [+] Generator found in HTML: {generator}", output_file)
            
            if "WordPress" in generator:
                log("      [!] This appears to be a WordPress site.", output_file)
        else:
            log("  [-] No generator meta tag found in the HTML.", output_file)
            
    except requests.RequestException as e:
        log(f"  [-] Error retrieving HTML: {e}", output_file)
    print(f"HTML generator check completed. Results saved to: {output_file}")

def crawl_site(url, output_file, max_depth=2):
    print(f"Starting recursive crawl on {url} (Max Depth: {max_depth})...")
    # Track visited URLs to prevent infinite loops
    visited = set()
    
    # Parse the base domain to keep the crawler in scope
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    base_domain = urlparse(url).netloc
    
    def crawl(current_url, depth):
        # Stop if we've reached the depth limit or already visited the page
        if depth > max_depth or current_url in visited:
            return
        visited.add(current_url)
        log(f"  [+] Crawling ({depth}/{max_depth}): {current_url}", output_file)
        
        try:
            response = requests.get(current_url, timeout=5)
            # Skip parsing if the response is an image, PDF, or other non-HTML content
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return
            
            # Parse the HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all anchor tags
            for link in soup.find_all('a'):
                href = link.get('href')
                if not href:
                    continue
                    
                # Build a full URL from relative links (e.g., /about -> https://example.com/about)
                full_url = urljoin(current_url, href)
                
                # Strip off fragments (e.g., #section1) to avoid crawling the same page multiple times
                full_url = full_url.split('#')[0]
                
                # Ensure we only recursively crawl internal links
                if urlparse(full_url).netloc == base_domain:
                    crawl(full_url, depth + 1)
                    
        except requests.RequestException as e:
            log(f"  [-] Error crawling {current_url}: {e}", output_file)

    log(f"\n[*] Starting recursive crawl on {url} (Max Depth: {max_depth})...", output_file)
    crawl(url, 0)
    print(f"Crawl completed. Total unique pages visited: {len(visited)}. Results saved to: {output_file}")

def check_unfinished_site(url, output_file):
    print(f"Checking {url} for unfinished/default boilerplate content...")
    log(f"\n[*] Checking {url} for unfinished/default boilerplate...", output_file)
    
    # Common strings left behind on unfinished or default server pages
    keywords = [
        "lorem ipsum", 
        "apache2 ubuntu default page", 
        "under construction", 
        "welcome to nginx", 
        "index of /",
        "just another wordpress site"
    ]
    
    try:
        # Use GET to retrieve the full HTML body
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            # Convert response text to lowercase for case-insensitive matching
            page_content = response.text.lower()
            
            # Find which keywords exist in the page content
            found_keywords = [kw for kw in keywords if kw in page_content]
            
            if found_keywords:
                log(f"  [!] Unfinished/Default content detected!", output_file)
                log(f"      Keywords found: {', '.join(found_keywords)}", output_file)
            else:
                log("  [-] No obvious unfinished content detected.", output_file)
        else:
            log(f"  [-] Received status {response.status_code}, skipping content check.", output_file)
            
    except requests.RequestException as e:
        log(f"  [-] Error checking content: {e}", output_file)
    print(f"Unfinished site check completed. Results saved to: {output_file}")

def find_version_leaks(body):
    # Scans a raw response body for leaked version strings and stack-trace signatures.
    if not body:
        return []

    version_patterns = [
        r'Apache/[\d.]+',
        r'nginx/[\d.]+',
        r'Microsoft-IIS/[\d.]+',
        r'(?:Apache[-\s]?)?Tomcat/[\d.]+',
        r'PHP/[\d.]+',
        r'OpenSSL/[\d.]+\w*',
        r'Werkzeug/[\d.]+',
        r'Python/[\d.]+',
        r'Jetty\([\d.]+\)',
        r'Express',
    ]
    # Signatures that suggest a debug stack trace / verbose error leaked through
    trace_signatures = [
        'Traceback (most recent call last)',
        'Exception',
        'at java.',
        'at org.apache',
        'Stacktrace',
        'Warning: ',
        'Fatal error',
        'SyntaxError',
        'ReferenceError',
    ]

    findings = set()
    for pattern in version_patterns:
        for match in re.findall(pattern, body, re.IGNORECASE):
            findings.add(match.strip())
    for sig in trace_signatures:
        if sig.lower() in body.lower():
            findings.add(f"Trace signature: '{sig}'")
    return sorted(findings)


def _probe_port(hostname, port, use_ssl, output_file):
    # Runs the malformed-request probes against a single host:port.
    log(f"\n[*] Banner grabbing on {hostname}:{port} ({'TLS' if use_ssl else 'plain'})...", output_file)

    probes = {
        "Baseline (HEAD)":        f"HEAD / HTTP/1.0\r\nHost: {hostname}\r\n\r\n",
        "Invalid HTTP version":   f"GET / HTTP/9.9\r\nHost: {hostname}\r\n\r\n",
        "Malformed request line": "GET /\r\n\r\n",
        "Unknown method":         f"XYZZY / HTTP/1.1\r\nHost: {hostname}\r\n\r\n",
    }

    for label, payload in probes.items():
        log(f"\n  [>] Probe: {label}", output_file)
        try:
            sock = socket.create_connection((hostname, port), timeout=5)

            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=hostname)

            sock.sendall(payload.encode('utf-8', errors='ignore'))

            sock.settimeout(5)
            response = b""
            try:
                while len(response) < 8192:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            finally:
                sock.close()

            decoded = response.decode('utf-8', errors='replace')
            if not decoded.strip():
                log("      [-] No response returned.", output_file)
                continue

            head, _, body = decoded.partition('\r\n\r\n')
            header_lines = head.splitlines()

            status_line = header_lines[0] if header_lines else "(none)"
            log(f"      Status line: {status_line}", output_file)

            interesting = ('server', 'x-powered-by', 'x-aspnet-version', 'via')
            for line in header_lines[1:]:
                if ':' in line and line.split(':', 1)[0].strip().lower() in interesting:
                    log(f"      {line.strip()}", output_file)

            leaks = find_version_leaks(body)
            if leaks:
                log("      [!] Possible version/trace disclosure in body:", output_file)
                for leak in leaks:
                    log(f"          - {leak}", output_file)

        except ConnectionRefusedError:
            log("      [-] Connection refused (port likely closed).", output_file)
        except socket.timeout:
            log("      [-] Connection timed out.", output_file)
        except (ssl.SSLError, OSError) as e:
            log(f"      [-] Connection/TLS error: {e}", output_file)
        except Exception as e:
            log(f"      [-] Error: {e}", output_file)


def grab_banner(url, output_file, ports=None):
    print(f"Starting banner grab sweep on {url}...")
    # Sweeps the malformed-request banner grab across multiple ports.
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    hostname = urlsplit(url).hostname

    # port -> is it a TLS port. Covers the common web + alt-web ports.
    default_ports = {
        80:   False,
        8080: False,
        8000: False,
        443:  True,
        8443: True,
        4433: True,
    }

    # Allow a caller-supplied port list; infer TLS from the known map,
    # defaulting unknown ports to plaintext.
    if ports is not None:
        port_map = {p: default_ports.get(p, False) for p in ports}
    else:
        port_map = default_ports

    log(f"\n{'='*40}\n[*] Starting banner grab sweep on {hostname}\n{'='*40}", output_file)

    for port in sorted(port_map):
        _probe_port(hostname, port, port_map[port], output_file)
    print(f"Banner grab sweep completed. Results saved to: {output_file}")



def scan_single_port(hostname, port, timeout=3):
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return port, "open"
    except ConnectionRefusedError:
        return port, "closed"
    except (socket.timeout, OSError):
        return port, "filtered"

def parse_ports(content):
    ports = set()
    for token in content.replace('\n', ',').replace('\r', ',').split(','):
        token = token.strip()
        if not token:
            continue
        if '-' in token:                      # a range like "19-26"
            try:
                lo, hi = (int(x) for x in token.split('-', 1))
            except ValueError:
                continue
            if 0 <= lo <= hi <= 65535:
                ports.update(range(lo, hi + 1))
        elif token.isdigit():
            p = int(token)
            if 0 <= p <= 65535:
                ports.add(p)
    return sorted(ports)

def threaded_port_scan(url, output_file, port_file, max_threads=50):
    print(f"Starting threaded port scan on {url} using ports from {port_file}...")
    # Orchestrates the threaded scanning using ports read from a file.
    KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 
    8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
}
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    hostname = urlsplit(url).hostname
    
    # 1. Read and parse the ports from the provided file
    ports_to_scan = []
    if not os.path.isfile(port_file):
        log(f"\n[-] Error: Port list file '{port_file}' not found.", output_file)
        return

    try:
        with open(port_file, 'r') as file:
            content = file.read()
            # Split by comma, strip whitespace, and keep only valid numbers
            ports_to_scan = parse_ports(content)
    except Exception as e:
        log(f"\n[-] Error reading port file: {e}", output_file)
        return

    if not ports_to_scan:
        log(f"\n[-] No valid numerical ports found in {port_file}.", output_file)
        return

    # Remove duplicates if the user accidentally typed the same port twice
    ports_to_scan = list(set(ports_to_scan))
    
    
    log(f"\n[*] Starting TCP Port Scan on {hostname} for {len(ports_to_scan)} ports (Threads: {max_threads})...", output_file)
    print("80 in list:", 80 in ports_to_scan, " 443 in list:", 443 in ports_to_scan)
    open_ports = []
    
    # 2. Execute the concurrent scan
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {
            executor.submit(scan_single_port, hostname, port): port 
            for port in ports_to_scan
        }
        
        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open = future.result()
            if is_open:
                service = KNOWN_SERVICES.get(port, "Unknown Service")
                log(f"  [+] Port {port}/TCP is OPEN ({service})", output_file)
                open_ports.append(port)
                
    if not open_ports:
        log("  [-] No open ports found from the provided list.", output_file)
    else:
        # Sort the results numerically before printing the final summary
        open_ports.sort()
        log(f"\n[*] Scan complete. Found {len(open_ports)} open ports: {open_ports}", output_file)
    print(f"Threaded port scan completed. Results saved to: {output_file}")