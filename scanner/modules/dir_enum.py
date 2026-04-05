import requests

COMMON_DIRS = [
    "admin",
    "login",
    "dashboard",
    "uploads",
    "images",
    "css",
    "js"
]

def dir_scan(url):
    print("\n[+] Running directory scan...\n")

    if not url.endswith("/"):
        url += "/"

    found = []

    for directory in COMMON_DIRS:
        target = url + directory

        try:
            response = requests.get(target, timeout=5)

            if response.status_code == 200:
                print(f"[+] Found: {target}")
                found.append(target)

        except:
            pass

    return found
