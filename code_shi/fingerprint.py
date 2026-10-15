import requests
from urllib.parse import urlsplit
import ssl
import socket
import dns.resolver
import os

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

def check_headers(url):
    output_file = setup_file(url);
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

def check_certificates(url):
    output_file = setup_file(url);
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
                    # Issuer: Certificate Authority (CA)
                    log("  Issuer:", cert.get("issuer"), output_file)
                    log("  Subject:", cert.get("subject"), output_file)
                    
        except ConnectionRefusedError:
            log("  [-] Port is closed (Connection refused).", output_file)
        except socket.timeout:
            log("  [-] Connection timed out (Port likely filtered by a firewall).", output_file)
        except ssl.SSLError:
            log("  [-] Port is open, but it is not running a standard SSL/TLS service.", output_file)
        except Exception as e:
            log(f"  [-] Unexpected error: {e}", output_file)

def check_default_files(url):
    output_file = setup_file(url)
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

def check_dns_records(url):
    output_file = setup_file(url)
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