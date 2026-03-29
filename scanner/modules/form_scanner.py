import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from utils.logger import log


# 🔹 Extract forms from page
def get_forms(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except:
        return []


# 🔹 Get form details
def get_form_details(form):
    details = {}

    action = form.get("action")
    method = form.get("method", "get").lower()

    inputs = []

    for input_tag in form.find_all("input"):
        name = input_tag.get("name")
        if name:
            inputs.append(name)

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs

    return details


# 🔹 Submit form with payload
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


# 🔹 Scan forms for vulnerabilities
def scan_forms(url):
    forms = get_forms(url)

    for form in forms:
        details = get_form_details(form)

        payloads = [
            "' OR 1=1--",
            "<script>alert(1)</script>"
        ]

        for payload in payloads:
            response = submit_form(details, url, payload)

            if response and payload in response.text:
                log(f"[FORM XSS] Possible: {url}")

            if response and any(err in response.text.lower() for err in ["sql", "syntax", "mysql"]):
                log(f"[FORM SQLi] Possible: {url}")
