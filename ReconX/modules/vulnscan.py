import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore

SQL_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
XSS_PAYLOADS = ["<script>alert(1)</script>"]

def get_forms(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except:
        return []

def get_form_details(form):
    details = {}
    action = form.attrs.get("action", "")
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        name = input_tag.attrs.get("name")
        if name:
            inputs.append(name)

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs

    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}

    for input_name in form_details["inputs"]:
        data[input_name] = payload

    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, timeout=5)
        else:
            return requests.get(target_url, params=data, timeout=5)
    except:
        return None

def scan_sql_xss(url):
    print(Fore.CYAN + "\n[+] Starting Vulnerability Scan...\n")

    forms = get_forms(url)

    if not forms:
        print(Fore.YELLOW + "[-] No forms found")
        return []

    vulnerabilities = []

    for form in forms:
        form_details = get_form_details(form)

        # SQL Injection
        for payload in SQL_PAYLOADS:
            res = submit_form(form_details, url, payload)
            if res and ("sql" in res.text.lower() or "syntax" in res.text.lower()):
                print(Fore.RED + f"[!] SQL Injection detected at {url}")
                vulnerabilities.append(f"SQLi: {url}")
                break

        # XSS
        for payload in XSS_PAYLOADS:
            res = submit_form(form_details, url, payload)
            if res and payload in res.text:
                print(Fore.RED + f"[!] XSS detected at {url}")
                vulnerabilities.append(f"XSS: {url}")
                break

    return vulnerabilities
