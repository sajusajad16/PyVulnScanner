import socket
import time
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore

# Common ports (you can expand later)
COMMON_PORTS = [21, 22, 80, 443, 8080, 445, 139]

def check_port(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        s.close()

        if result == 0:
            time.sleep(0.05)  # prevents messy output
            print(Fore.GREEN + f"[+] Open Port: {port}")
            return port

    except:
        pass

    return None


def run_port_scan(target):
    print(Fore.CYAN + "\n[+] Starting Port Scan...\n")

    open_ports = []

    # Threading for speed
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda port: check_port(target, port), COMMON_PORTS)

        for r in results:
            if r:
                open_ports.append(r)

    # Clean summary
    print(Fore.YELLOW + f"\n[+] Total Open Ports: {len(open_ports)}\n")

    return open_ports
