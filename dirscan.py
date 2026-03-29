import requests
from colorama import Fore
from concurrent.futures import ThreadPoolExecutor

found = []

def load_wordlist(file):
    try:
        with open(file, "r") as f:
            return [line.strip() for line in f]
    except:
        print("[-] Wordlist not found!")
        return []


def check_dir(url, word):
    global found
    full_url = f"{url.rstrip('/')}/{word}"

    try:
        r = requests.get(full_url, timeout=2)

        if r.status_code in [200, 301, 302, 403]:
            print(Fore.CYAN + f"[FOUND] {full_url} ({r.status_code})")
            found.append(full_url)

    except:
        pass


def scan_dirs(url):
    print("\n[+] Directory Scanning (Wordlist + Threaded)...\n")

    wordlist = load_wordlist("wordlist.txt")

    if not wordlist:
        return []

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(lambda w: check_dir(url, w), wordlist)

    return found
