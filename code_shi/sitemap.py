import requests
from pathlib import Path
from urllib.parse import urlparse

# Checks if a given URL is valid by sending a GET request and checking the response status code
def check_url(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        if response.status_code in [200, 204, 301, 302, 307, 308, 401, 403, 405]:
            return True
        else:
            return False
    except requests.RequestException:
        return False

def create_folder(folder_name):
     # Create a folder if it doesn't exist
    Path(folder_name).mkdir(parents=True, exist_ok=True)

# Writes the valid URLs to a file.
def write_to_file(filename, data):
    with open(filename, 'a') as file:
        file.write(data + '\n')

# Goes through a list of directories and checks if they exist on the target URL. If they do, it writes the valid URLs to a file.
def check_directory_list(target_url, directory_list):
    # Parse the target URL to create a safe filename for storing results
    parsed_url = urlparse(target_url)
    # Create a safe filename by replacing ':' with '_'
    safe_domain = parsed_url.netloc.replace(':', '_')
    create_folder("Directory_Numeration_Results")
    try:
        with open(directory_list, 'r') as file:
            directories = file.readlines()
        for directory in directories:
            directory = directory.strip()
            full_url = f"{target_url}/{directory}"
            if check_url(full_url):
                write_to_file("Directory_Numeration_Results/" + safe_domain + '_directories.txt', full_url)
    except FileNotFoundError:
                print(f"Directory list file '{directory_list}' not found.")
                return
    except Exception as e:
                print(f"An error occurred: {e}")
                return

def load_classifications(classification_file):
    # Load classifications from a file and return a dictionary mapping paths to their risk levels.
    classifications = {}
    current_risk = "Unclassified"
    if (not Path(classification_file).is_file()):
        print(f"Classification file '{classification_file}' not found.")
        return classifications
    
    with open(classification_file, 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            if "critical" in line.lower():
                current_risk = "Critical"
            elif "high" in line.lower():
                current_risk = "High"
            elif "medium" in line.lower():
                current_risk = "Medium"
            elif "low" in line.lower():
                current_risk = "Low"
            elif line.startswith("/"):
                path = line.split()[0].split(',')[0].strip()
                classifications[path] = current_risk

    # Sort the classifications dictionary by the length of the paths in descending order and return it.
    return dict(sorted(classifications.items(), key=lambda item: len(item[0]), reverse=True))


def classify_path(directories_file, classification_file):
    # Classifies the paths in the directories file based on the classifications loaded from the classification file.
    if (not Path(directories_file).is_file()):
        print(f"Directories file '{directories_file}' not found.")
        return
    classifications = load_classifications(classification_file)
    if not classifications:
        print("No classifications loaded. Exiting.")
        return
    output_file = directories_file.replace('.txt', '_classified.txt')
    with open(directories_file, 'r') as dir_file, open(output_file, 'w') as out_file:
        for line in dir_file:
            line = line.strip()
            if not line:
                continue
            path = line if line.startswith("/") else "/" + line
            assigned_risk = "Unclassified"
            for classified_path, risk in classifications.items():
                if path.startswith(classified_path):
                    assigned_risk = risk
                    break
            out_file.write(f"{line} - {assigned_risk}\n")
    
    
check_directory_list("https://localhost:3000", "C:\\Users\\mabdu\\Downloads\\School\\Computer\\Web-Application-Security-Scanner\\lists\\Web-Content\\common_directories.txt")
classify_path("C:\\Users\\mabdu\\Downloads\\School\\Computer\\Web-Application-Security-Scanner\\Directory_Numeration_Results\\localhost_3000_directories.txt", "C:\\Users\\mabdu\\Downloads\\School\\Computer\\Web-Application-Security-Scanner\\lists\\classified_directory_list.txt")