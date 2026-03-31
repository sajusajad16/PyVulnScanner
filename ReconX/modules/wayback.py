import requests
from colorama import Fore

def get_wayback_urls(domain):
    print(Fore.CYAN + "\n[+] Fetching Wayback URLs...\n")

    urls = []
    api = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"

    try:
        res = requests.get(api, timeout=10)
        data = res.json()

        for item in data[1:]:
            urls.append(item[0])

        for u in urls[:10]:
            print(Fore.GREEN + f"[+] {u}")

    except:
        print(Fore.RED + "[-] Failed to fetch Wayback URLs")

    return urls
