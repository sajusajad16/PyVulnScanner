import requests
from colorama import Fore

PAYLOAD = "<script>alert(1)</script>"

def fuzz_xss(urls):
    print(Fore.CYAN + "\n[+] Starting Parameter Fuzzing...\n")

    vulnerable = []

    for url in urls:
        test_url = url.replace("test", PAYLOAD)

        try:
            res = requests.get(test_url, timeout=5)

            if PAYLOAD in res.text:
                print(Fore.RED + f"[!] Reflected XSS possible: {test_url}")
                vulnerable.append(test_url)

        except:
            pass

    return vulnerable
