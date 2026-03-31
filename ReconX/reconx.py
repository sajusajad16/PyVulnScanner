import argparse
import socket
from colorama import Fore, init

# Core
from core.targets import load_targets
from core.report import save_report
from core.html_report import generate_html_report

# Modules
from modules.subdomain import run_subdomain_scan
from modules.ports import run_port_scan
from modules.dirscan import run_dir_scan

init(autoreset=True)

VERSION = "ReconX v7.0 SMART FRAMEWORK"

def banner():
    print(Fore.CYAN + f"""
    ==========================================
            {VERSION}
     Advanced Pentesting Framework
    ==========================================
    """)

def clean_url(url):
    return url.replace("https://", "").replace("http://", "").strip("/")

# 🔥 NEW: Detect IP
def is_ip(target):
    try:
        socket.inet_aton(target)
        return True
    except:
        return False

def scan_target(target, args):
    print(Fore.GREEN + f"\n[+] Scanning: {target}")

    ip_mode = is_ip(target)

    if ip_mode:
        print(Fore.YELLOW + "[*] Detected IP address")
    else:
        print(Fore.YELLOW + "[*] Detected Domain")

    results = {
        "target": target,
        "subdomains": [],
        "ports": [],
        "directories": []
    }

    # 🔹 SUBDOMAIN (ONLY FOR DOMAIN)
    if args.subdomain and not ip_mode:
        print(Fore.BLUE + "[*] Subdomain scan enabled")
        results["subdomains"] = run_subdomain_scan(target) or []

    elif args.subdomain and ip_mode:
        print(Fore.YELLOW + "[-] Skipping subdomain scan (IP detected)")

    # 🔹 PORT SCAN (BOTH)
    if args.ports:
        print(Fore.BLUE + "[*] Port scan enabled")
        results["ports"] = run_port_scan(target) or []

    # 🔹 DIRECTORY SCAN (BOTH)
    if args.dir:
        print(Fore.BLUE + "[*] Directory scan enabled")
        results["directories"] = run_dir_scan(target, args.wordlist) or []

    # SAVE REPORT
    save_report(results, target)
    generate_html_report(results, target)

def main():
    parser = argparse.ArgumentParser(description="ReconX Framework")

    # Input
    parser.add_argument("-u", "--url", help="Single target")
    parser.add_argument("-f", "--file", help="Multiple targets file")

    # Modules
    parser.add_argument("--subdomain", action="store_true")
    parser.add_argument("--ports", action="store_true")
    parser.add_argument("--dir", action="store_true")

    parser.add_argument("--wordlist", help="Wordlist for directory scan")

    parser.add_argument("--full", action="store_true")
    parser.add_argument("--version", action="store_true")

    args = parser.parse_args()

    if args.version:
        print(VERSION)
        return

    banner()

    # FULL MODE
    if args.full:
        args.subdomain = True
        args.ports = True
        args.dir = True

    targets = []

    # Single target
    if args.url:
        targets.append(clean_url(args.url))

    # Multiple targets
    if args.file:
        targets.extend(load_targets(args.file))

    if not targets:
        print("[-] Provide -u or -f")
        return

    # Scan all targets
    for t in targets:
        scan_target(t, args)

    print(Fore.CYAN + "\n[+] All scans completed\n")


if __name__ == "__main__":
    main()
