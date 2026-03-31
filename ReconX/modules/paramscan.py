import requests
from colorama import Fore

COMMON_PARAMS = ["id", "page", "q", "search", "file", "url"]

def scan_params(target):
    print(Fore.CYAN + "\n[+] Starting Parameter Scan...\n")

    found = []

    for param in COMMON_PARAMS:
        url = f"http://{target}/?{param}=test"
        try:
            res = requests.get(url, timeout=5)

            if res.status_code == 200:
                print(Fore.GREEN + f"[+] Found parameter: {param}")
                found.append(url)
        except:
            pass

    return found
