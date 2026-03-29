import requests
from utils.logger import log


# 🔹 Load payloads from file
def load_payloads():
    try:
        with open("payloads/sqli.txt", "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        log("[ERROR] sqli.txt not found!")
        return []


# 🔹 Detect SQL errors in response
def is_sqli_vulnerable(response_text):
    errors = [
        "sql syntax",
        "mysql",
        "sqlite",
        "postgresql",
        "syntax error",
        "unexpected token",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated"
    ]

    return any(error in response_text.lower() for error in errors)


# 🔹 Main SQLi testing function
def test_sqli(url):
    payloads = load_payloads()

    if not payloads:
        return

    for payload in payloads:

        try:
            # 🔸 Case 1: URL has parameter (e.g. ?id=1)
            if "=" in url:
                base, param = url.split("=", 1)
                test_url = base + "=" + payload
            else:
                # 🔸 Case 2: Append payload directly
                test_url = url + payload

            response = requests.get(test_url, timeout=5)

            if is_sqli_vulnerable(response.text):
                log(f"[SQLi] Possible vulnerability: {test_url}")

        except requests.exceptions.RequestException:
            continue
