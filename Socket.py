import socket

def scan_ports(target_host, port_range):
    for port in range(*port_range):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((target_host, port))
                print(f"Port {port} is open")
        except (socket.timeout, ConnectionRefusedError):
            pass

# Get input from the user
target_host = input("Enter the target host: ")
port_range = input("Enter the port range (e.g., 1-1024): ").split('-')
port_range = (int(port_range[0]), int(port_range[1]) + 1)
scan_ports(target_host, port_range)
