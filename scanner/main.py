from crawler import crawl
from modules import sqli, xss, headers, dir_enum
from modules import form_scanner, port_scanner   # ✅ NEW
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse               # ✅ NEW


# 🔹 Scan each URL
def scan_url(url):
    print(f"[+] Testing: {url}")

    sqli.test_sqli(url)
    xss.test_xss(url)

    # 🔥 NEW → Form scanning
    form_scanner.scan_forms(url)


# 🔹 Main function
def main():
    print("""
====================================
   PyVulnScanner v2.0
====================================
""")

    target = input("Enter target URL: ").strip()

    # 🔥 NEW → Extract host for port scanning
    parsed = urlparse(target)
    host = parsed.netloc or parsed.path

    # 🔥 NEW → Run port scanner BEFORE crawling
    port_scanner.scan_ports(host)

    print("\n[+] Crawling target...\n")
    urls = crawl(target)

    # ✅ fallback if no URLs found
    if not urls:
        print("[!] No URLs found by crawler, using target URL\n")
        urls = [target]

    print(f"[+] Found {len(urls)} URLs\n")

    # 🔹 Multi-thread scanning
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(scan_url, urls)

    print("\n[+] Checking security headers...\n")
    headers.check_headers(target)

    print("\n[+] Running directory scan...\n")
    dir_enum.dir_scan(target)

    print("\n[✓] Scan Completed. Check report.txt\n")


# 🔹 Entry point
if __name__ == "__main__":
    main()
