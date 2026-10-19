import requests
from pathlib import Path
from urllib.parse import urlparse
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed


# Shared session. The custom adapter sizes the connection pool to the worker
# count — without it urllib3 caps the pool at 10 and logs "pool is full"
# warnings under higher concurrency. Keep pool_maxsize >= max_workers.
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "Mozilla/5.0 (compatible; WebScanner/1.0)"})
_adapter = requests.adapters.HTTPAdapter(pool_connections=32, pool_maxsize=32)
SESSION.mount("http://", _adapter)
SESSION.mount("https://", _adapter)

EXISTS_CODES = {200, 204, 206, 301, 302, 307, 308, 401, 403, 405, 500, 503}


# --- get_baseline and check_url are the versions from before, now using SESSION.
# Baseline is computed once and only read by workers, so it's safe to share. ---

def get_baseline(target_url):
    random_path = secrets.token_hex(16)
    url = f"{target_url.rstrip('/')}/{random_path}"
    try:
        resp = SESSION.get(url, timeout=5, allow_redirects=False)
    except requests.RequestException:
        return None
    return {
        "status": resp.status_code,
        "length": len(resp.content),
        "location": resp.headers.get("Location"),
        "soft_404": resp.status_code in EXISTS_CODES,
    }


def check_url(url, baseline=None, length_tolerance=0.10):
    try:
        resp = SESSION.get(url, timeout=5, allow_redirects=False)
    except requests.RequestException:
        return None

    status, length = resp.status_code, len(resp.content)
    if status not in EXISTS_CODES:
        return None
    if baseline is None or not baseline["soft_404"]:
        return {"url": url, "status": status, "length": length}

    if status in (301, 302, 307, 308):
        if status == baseline["status"] and resp.headers.get("Location") == baseline["location"]:
            return None
        return {"url": url, "status": status, "length": length}

    if baseline["length"]:
        similar = abs(length - baseline["length"]) / baseline["length"] <= length_tolerance
    else:
        similar = length == 0
    if status == baseline["status"] and similar:
        return None
    return {"url": url, "status": status, "length": length}


# --- Pure worker: takes a URL, returns a result dict (or None). No I/O here. ---

def _probe(url, is_archive, baseline):
    result = check_url(url, baseline)
    if result:
        result["is_archive"] = is_archive
    return result


def check_directory_list(target_url, directory_list, max_workers=15):
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    # Strip trailing slash ONCE. get_baseline already strips before joining,
    # so without this the probe URLs get a double slash and don't match the
    # baseline's path shape — every probe lands on the soft-404 page.
    target_url = target_url.rstrip("/")

    parsed_url = urlparse(target_url)
    safe_domain = parsed_url.netloc.replace(':', '_')
    create_folder("Directory_Numeration_Results")
    output_file = f"Directory_Numeration_Results/{safe_domain}_directories.txt"

    archive_extensions = ['.bak', '.old', '.tar.gz', '.zip', '.sql']

    try:
        with open(directory_list, 'r') as file:
            directories = file.readlines()
    except FileNotFoundError:
        print(f"Directory list file '{directory_list}' not found.")
        return

    baseline = get_baseline(target_url)
    if baseline is None:
        print("[!] Baseline request failed — target unreachable or URL malformed. Aborting.")
        return
    print(f"[*] Baseline OK: status {baseline['status']}, "
          f"{baseline['length']} bytes, soft_404={baseline['soft_404']}")

    tasks = []
    for directory in directories:
        directory = directory.strip().lstrip("/")   # guard leading slash in wordlist
        if not directory:
            continue
        clean_dir = directory.rstrip('/')
        tasks.append((f"{target_url}/{directory}", False))
        for ext in archive_extensions:
            tasks.append((f"{target_url}/{clean_dir}{ext}", True))

    print(f"[*] Concurrent enumeration on {target_url} "
          f"({len(tasks)} requests, {max_workers} workers)...")

    found = filtered = errors = processed = 0
    with open(output_file, 'a') as out, \
         ThreadPoolExecutor(max_workers=max_workers) as executor:

        futures = {
            executor.submit(_probe, url, is_archive, baseline): url
            for url, is_archive in tasks
        }

        for future in as_completed(futures):
            processed += 1
            try:
                result = future.result()
            except Exception as e:
                errors += 1
                print(f"  [-] Worker error on {futures[future]}: {e}")
                continue

            if not result:
                filtered += 1
            else:
                found += 1
                if result["is_archive"]:
                    line = f"{result['url']} (Archive) [{result['status']}]"
                    print(f"  [!] EXPOSED ARCHIVE: {result['url']} ({result['status']})")
                else:
                    line = f"{result['url']} [{result['status']}]"
                    print(f"  [+] Found: {result['url']} ({result['status']})")
                out.write(line + "\n")
                out.flush()

            # Heartbeat: proves the scan is alive even when nothing is a hit.
            if processed % 500 == 0:
                print(f"  [...] {processed}/{len(tasks)} checked "
                      f"({found} found, {filtered} filtered, {errors} errors)")

    print(f"[*] Done. {found} found, {filtered} filtered, {errors} errors, "
          f"out of {len(tasks)} checked.")

def create_folder(folder_name):
     # Create a folder if it doesn't exist
    Path(folder_name).mkdir(parents=True, exist_ok=True)


