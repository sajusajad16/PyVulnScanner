import requests
from utils.logger import log


def load_payloads():
    try:
        with open("payloads/xss.txt", "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        log("[ERROR] xss.txt not found!")
        return []


def test_xss(url):
    payloads = load_payloads()

    for payload in payloads:
        test_url = url + payload

        try:
            res = requests.get(test_url, timeout=5)

            if payload in res.text:
                log(f"[XSS] Vulnerable: {test_url}")

        except:
            continue
