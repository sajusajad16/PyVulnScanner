import socket
from dirscan import scan_dirs
from vulnscan import test_sqli, test_xss
from report import save_report


def grab_banner(target, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))

        if port == 80:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")

        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()

        return banner if banner else "No banner"

    except:
        return "Unknown"


def scan_ports(target):
    print("\n[+] Port Scanning + Banner Grabbing...\n")

    open_ports = []
    banners = {}

    ports = [21, 22, 80, 139, 445]

    for port in ports:
        print(f"[*] Checking port {port}")  # DEBUG

        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((target, port))

            print(f"[OPEN] Port {port}")

            banner = grab_banner(target, port)
            print(f"   ↳ Banner: {banner[:60]}")

            open_ports.append(port)
            banners[port] = banner

            s.close()

        except:
            pass

    return open_ports, banners


if __name__ == "__main__":
    print("🚀 ReconX Scanner Started\n")

    target = input("Enter target IP: ").strip()
    website = input("Enter website (http://example.com): ").strip()

    print("\n[+] Starting Scan...\n")

    # Port scan + banner
    ports, banners = scan_ports(target)

    # Directory scan
    dirs = scan_dirs(website)

    # Vulnerability scan
    vulns = []

    for d in dirs:
        if test_sqli(d):
            vulns.append(f"SQLi → {d}")

        if test_xss(d):
            vulns.append(f"XSS → {d}")

    # Report data
    report_data = {
        "target": target,
        "open_ports": ports,
        "banners": banners,
        "directories": dirs,
        "vulnerabilities": vulns
    }

    # Save report
    save_report(report_data)

    print("\n[+] Scan Completed ✅")
