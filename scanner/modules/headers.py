import requests

def check_headers(url):
    print("\n[+] Checking security headers...\n")

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "X-Content-Type-Options"
        ]

        for header in security_headers:
            if header in headers:
                print(f"[+] {header}: Present")
            else:
                print(f"[-] {header}: Missing")

    except Exception as e:
        print(f"[ERROR] {e}")
