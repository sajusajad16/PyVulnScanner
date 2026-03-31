import requests
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore

def check_subdomain(sub, domain):
    url = f"http://{sub}.{domain}"
    try:
        res = requests.get(url, timeout=3)
        if res.status_code < 400:
            print(Fore.GREEN + f"[+] Found: {url}")
    except:
        pass

def run_subdomain_scan(domain):
    print(Fore.CYAN + "\n[+] Starting Subdomain Scan...\n")

    wordlist = [
        "www", "mail", "ftp", "admin", "test",
        "dev", "api", "blog", "portal", "vpn"
    ]

    with ThreadPoolExecutor(max_workers=20) as executor:
        for sub in wordlist:
            executor.submit(check_subdomain, sub, domain)
