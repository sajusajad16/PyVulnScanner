import requests
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore

def load_wordlist(path):
    try:
        with open(path, "r") as f:
            return [line.strip() for line in f]
    except:
        return ["admin", "login", "dashboard"]

def check_directory(target, word):
    url = f"http://{target}/{word}"

    try:
        res = requests.get(url, timeout=3)
        if res.status_code < 400:
            print(Fore.GREEN + f"[+] Found: {url}")
            return url
    except:
        pass

    return None

def run_dir_scan(target, wordlist_path=None):
    print(Fore.CYAN + "\n[+] Starting Directory Scan...\n")

    words = load_wordlist(wordlist_path) if wordlist_path else ["admin","login","test"]

    results = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        for result in executor.map(lambda w: check_directory(target, w), words):
            if result:
                results.append(result)

    return results
