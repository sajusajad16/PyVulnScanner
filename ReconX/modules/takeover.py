import requests
from colorama import Fore

TAKEOVER_SIGNATURES = [
    "There isn't a GitHub Pages site here",
    "NoSuchBucket",
    "Heroku | No such app"
]

def check_takeover(subdomains):
    print(Fore.CYAN + "\n[+] Checking Subdomain Takeover...\n")

    vulnerable = []

    for sub in subdomains:
        try:
            res = requests.get(sub, timeout=5)

            for sig in TAKEOVER_SIGNATURES:
                if sig.lower() in res.text.lower():
                    print(Fore.RED + f"[!] Possible Takeover: {sub}")
                    vulnerable.append(sub)

        except:
            pass

    return vulnerable
