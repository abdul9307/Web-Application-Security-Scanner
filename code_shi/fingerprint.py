import requests
from urllib.parse import urlsplit
import ssl
import socket
import dns.resolver



def check_headers(url):
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
                print(f"{header}: {response.headers[header]}")
    except requests.RequestException as e:
        print(f"Error connecting to target: {e}")

def check_certificates(url):
    # Checks SSL certificate
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    hostname = urlsplit(url).hostname
    # 443,8443, 4433: HTTPS, 993: IMAP, 80: HTTP
    ports = [443, 8443, 4433, 993, 80]

    # Creates an SSL context object: default secure settings with certificate validation
    context = ssl.create_default_context()
    for port in ports:
        print(f"\n[*] Testing {hostname} on port {port}...")
    
        try:
            # Opens a standard TCP connection to target port
            with socket.create_connection((hostname, port), timeout=3) as sock:
                # Wraps TCP connection in SSL context
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # returns SSL certificate
                    cert = ssock.getpeercert()
                    print("  [+] SSL Certificate found!")
                    # Issuer: Certificate Authority (CA)
                    print("  Issuer:", cert.get("issuer"))
                    print("  Subject:", cert.get("subject"))
                    
        except ConnectionRefusedError:
            print("  [-] Port is closed (Connection refused).")
        except socket.timeout:
            print("  [-] Connection timed out (Port likely filtered by a firewall).")
        except ssl.SSLError:
            print("  [-] Port is open, but it is not running a standard SSL/TLS service.")
        except Exception as e:
            print(f"  [-] Unexpected error: {e}")

def check_default_files(url):
    # Ensure the base URL doesn't end with a slash so we don't get double slashes
    base_url = url.rstrip('/')
    files_to_check = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/humans.txt"]
    
    print(f"\n[*] Checking for default files on {base_url}...")
    for file in files_to_check:
        target_url = base_url + file
        try:
            # We use GET here instead of HEAD because sometimes servers return 200 
            # for a HEAD request even if the file is just a custom 404 page.
            response = requests.get(target_url, timeout=5)
            if response.status_code == 200:
                print(f"  [+] Found: {target_url}")
            else:
                print(f"  [-] Not Found (Status {response.status_code}): {file}")
        except requests.RequestException as e:
            print(f"  [-] Error checking {file}: {e}")

def check_dns_records(url):
    # Parse the domain out of the URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    domain = urlsplit(url).hostname
    # Remove 'www.' if present, as DNS records are usually on the root domain
    if domain.startswith('www.'):
        domain = domain[4:]
        
    print(f"\n[*] Checking DNS Records for {domain}...")
    # A: IP4 addresses, MX: Mail exchange records, TXT: Text records
    record_types = ['A', 'MX', 'TXT']
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            print(f"\n  [+] {record} Records Found:")
            for rdata in answers:
                print(f"      - {rdata.to_text()}")
        except dns.resolver.NoAnswer:
            print(f"\n  [-] No {record} records found.")
        except dns.resolver.NXDOMAIN:
            print(f"\n  [-] Domain {domain} does not exist.")
            break # If the domain doesn't exist, stop checking other records
        except Exception as e:
            print(f"\n  [-] Error retrieving {record} records: {e}")