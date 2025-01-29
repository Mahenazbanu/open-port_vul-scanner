import socket
import ssl

# Common ports to scan
COMMON_PORTS = [21, 22, 80, 443, 8080, 8443]

def port_scan(target):
    open_ports = []
    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    if open_ports:
        return f"Open ports on {target}: {', '.join(map(str, open_ports))}"
    return f"No open ports found for {target}"

def vulnerability_scan(target):
    results = []
    VULNERABLE_VERSIONS = {
        'Apache': ['2.4.49', '2.4.50'],
        'Nginx': ['1.20.0', '1.21.3'],
        'OpenSSH': ['8.3p1']
    }

    # Check HTTP services
    for port in [80, 443, 8080, 8443]:
        try:
            # Establish connection
            context = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=2) as sock:
                if port in [443, 8443]:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        self_signed = False
                        try:
                            ssock.do_handshake()
                        except ssl.SSLCertVerificationError:
                            self_signed = True
                        self.check_http_service(ssock, port, target, VULNERABLE_VERSIONS, results, self_signed)
                else:
                    self.check_http_service(sock, port, target, VULNERABLE_VERSIONS, results)
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue

    # Check SSH service
    try:
        with socket.create_connection((target, 22), timeout=2) as sock:
            banner = sock.recv(1024).decode(errors='ignore')
            if 'OpenSSH' in banner:
                version = banner.split('OpenSSH_', 1)[1].split()[0]
                if version in VULNERABLE_VERSIONS['OpenSSH']:
                    results.append(f"⚠️ Vulnerable OpenSSH version detected ({version}) on port 22")
                else:
                    results.append(f"🔒 OpenSSH version {version} on port 22")
    except:
        pass

    return "\n".join(results) if results else f"No vulnerabilities detected for {target}"

def check_http_service(sock, port, target, vulnerable_versions, results, self_signed=False):
    try:
        sock.send(f"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
        response = sock.recv(4096).decode(errors='ignore')
        
        server_header = next((line.split(':', 1)[1].strip() for line in response.split('\n') 
                            if line.lower().startswith('server:')), None)
        
        if server_header:
            self.check_server_version(server_header, port, vulnerable_versions, results)
            
        if self_signed:
            results.append(f"🔓 Self-signed certificate detected on port {port}")

    except (socket.timeout, OSError):
        pass

def check_server_version(server_header, port, vulnerable_versions, results):
    for software in ['Apache', 'Nginx']:
        if software in server_header:
            version = server_header.split(f"{software}/")[-1].split()[0]
            if version in vulnerable_versions.get(software, []):
                results.append(f"⚠️ Vulnerable {software} version detected ({version}) on port {port}")
            else:
                results.append(f"🔒 {software} version {version} on port {port}")
            break
    else:
        results.append(f"ℹ️ Unknown server software detected on port {port}: {server_header}")
