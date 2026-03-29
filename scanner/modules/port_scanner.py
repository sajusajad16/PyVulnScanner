import socket
from utils.logger import log


def scan_ports(target):
    print("\n[+] Starting Port Scan...\n")

    ports = [21, 22, 23, 25, 53, 80, 443, 8080]

    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(1)

            result = sock.connect_ex((target, port))

            if result == 0:
                log(f"[PORT] Open: {target}:{port}")

            sock.close()

        except:
            continue
