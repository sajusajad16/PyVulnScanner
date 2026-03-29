import socket

def scan_port(target, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"[OPEN] Port {port}")
            return port
        sock.close()
    except:
        pass

def scan_target(target):
    ports = [21, 22, 80, 443]
    open_ports = []

    for port in ports:
        result = scan_port(target, port)
        if result:
            open_ports.append(result)

    return open_ports
