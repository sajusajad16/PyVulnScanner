import requests
from colorama import Fore

def test_sqli(url):
    payload = "' OR 1=1--"

    try:
        r = requests.get(url + payload, timeout=2)

        if "sql" in r.text.lower() or "syntax" in r.text.lower():
            print(Fore.RED + f"[VULN] SQL Injection → {url}")
            return True

    except:
        pass

    return False


def test_xss(url):
    payload = "<script>alert(1)</script>"

    try:
        r = requests.get(url + payload, timeout=2)

        if payload in r.text:
            print(Fore.RED + f"[VULN] XSS → {url}")
            return True

    except:
        pass

    return False
