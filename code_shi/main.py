import fingerprint
import sitemap
from urllib.parse import urlparse

target_url = input("\nEnter the target URL (e.g., example.com): ").strip()
parsed_url = urlparse(target_url)
safe_domain = parsed_url.netloc.replace(':', '_')
classified_list = r"C:\Users\mabdu\Downloads\School\Computer\Web-Application-Security-Scanner\lists\classified_directory_list.txt"
output_file = fingerprint.setup_file(target_url);

# sitemap.check_directory_list(target_url, "C:\\Users\\mabdu\\Downloads\\School\\Computer\\Web-Application-Security-Scanner\\lists\\Web-Content\\common.txt")
results_file = fr"C:\Users\mabdu\Downloads\School\Computer\Web-Application-Security-Scanner\code_shi\Directory_Numeration_Results\{safe_domain}_directories.txt"
print(f"Directory numeration results will be saved to: {results_file}")
fingerprint.check_headers(target_url, output_file)
fingerprint.check_certificates(target_url, output_file)
fingerprint.check_http_methods(target_url, output_file)
fingerprint.check_html_generator(target_url, output_file)
fingerprint.check_default_files(target_url, output_file)
fingerprint.check_dns_records(target_url, output_file)
fingerprint.check_html_generator(target_url, output_file)
fingerprint.check_unfinished_site(target_url, output_file)
fingerprint.crawl_site(target_url, output_file)
fingerprint.enumerate_subdomains(target_url, output_file)
fingerprint.check_waf(target_url, output_file)
fingerprint.threaded_port_scan(target_url, output_file, "C:\\Users\\mabdu\\Downloads\\School\\Computer\\Web-Application-Security-Scanner\\lists\\Infrastructure\\nmap-ports-top1000.txt")
