import fingerprint
import sitemap
from urllib.parse import urlparse

target_url = input("\nEnter the target URL (e.g., example.com): ").strip()
parsed_url = urlparse(target_url)
safe_domain = parsed_url.netloc.replace(':', '_')
classified_list = r"C:\Users\mabdu\Downloads\School\Computer\Web-Application-Security-Scanner\lists\classified_directory_list.txt"

sitemap.check_directory_list(target_url, "C:\\Users\\mabdu\\Downloads\\School\\Computer\\Web-Application-Security-Scanner\\lists\\Web-Content\\common_directories.txt")
results_file = fr"C:\Users\mabdu\Downloads\School\Computer\Web-Application-Security-Scanner\Directory_Numeration_Results\{safe_domain}_directories.txt"
sitemap.classify_path(results_file, "C:\\Users\\mabdu\\Downloads\\School\\Computer\\Web-Application-Security-Scanner\\lists\\classified_directory_list.txt")
fingerprint.check_headers(target_url)
fingerprint.check_certificates(target_url)
fingerprint.check_default_files(target_url)
fingerprint.check_dns_records(target_url)
