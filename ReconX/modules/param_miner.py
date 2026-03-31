from urllib.parse import urlparse, parse_qs
from colorama import Fore

def extract_params(urls):
    print(Fore.CYAN + "\n[+] Extracting Parameters from URLs...\n")

    params = set()

    for url in urls:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

        for param in query:
            params.add(param)

    for p in params:
        print(Fore.GREEN + f"[+] Param: {p}")

    return list(params)
