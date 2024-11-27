import socket
import requests

# Port scan function with port range
def port_scan(target, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    if open_ports:
        return f"Open ports on {target}: {', '.join(map(str, open_ports))}"
    else:
        return f"No open ports found for {target}"

# Vulnerability scan function (using a simple placeholder, can be expanded)
def vulnerability_scan(target):
    try:
        response = requests.get(f"http://{target}")
        if response.status_code == 200:
            return f"Vulnerability scan successful for {target}. HTTP Status: 200 OK"
        else:
            return f"Vulnerability scan for {target} returned HTTP Status: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Error during vulnerability scan for {target}: {str(e)}"
