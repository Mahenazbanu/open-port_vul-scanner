from vulners import Vulners

def vulnerability_scanner(target):
    vulners = Vulners(api_key='YOUR_API_KEY_HERE')
    results = []

    ports = [80, 443, 8080]
    for port in ports:
        try:
            if port == 80:
                software = 'apache'
            elif port == 443:
                software = 'nginx'
            else:
                software = None

            if software:
                vulns = vulners.search(software)
                if vulns:
                    results.append(f"Port {port} vulnerabilities: {len(vulns)} found.")
                else:
                    results.append(f"No vulnerabilities found for {software} on port {port}.")
            else:
                results.append(f"No known software detected on port {port}.")
        except Exception as e:
            results.append(f"Error fetching vulnerabilities for port {port}: {str(e)}")

    return "\n".join(results)
