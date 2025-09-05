import nmap
import requests
import socket


def scan_subdomain_ports(subdomain, nmap_args=None):
    """Scan subdomain for open ports and services using nmap + HTTP fallback."""
    scan_data = {
        'ip_address': '',
        'is_active': 'no',
        'open_ports': [],
        'services': {}
    }
    nmap_found_ports = False
    try:
        nm = nmap.PortScanner()
        # Use top 100 ports
        nmap_scan_args = nmap_args if nmap_args else "--top-ports 100"
        result = nm.scan(subdomain, arguments=nmap_scan_args)
        if result['scan']:
            for host_ip, host_data in result['scan'].items():
                scan_data['ip_address'] = host_ip
                scan_data['is_active'] = host_data['status']['state']
                if 'tcp' in host_data:
                    for port, port_info in host_data['tcp'].items():
                        if port_info['state'] == 'open':
                            scan_data['open_ports'].append(port)
                            nmap_found_ports = True
                            service_info = {
                                'name': port_info.get('name', 'unknown'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'state': port_info['state']
                            }
                            scan_data['services'][str(port)] = service_info
                break
    except Exception as e:
        print(f"[nmap] Scan failed: {e}")
    if not nmap_found_ports:
        # HTTP fallback if nmap did not find open ports
        test_ports = [
            (80, 'http'),
            (443, 'https'),
            (8080, 'http-alt'),
            (8443, 'https-alt')
        ]
        for port, service in test_ports:
            try:
                if port in [443, 8443]:
                    url = f"https://{subdomain}:{port}" if port != 443 else f"https://{subdomain}"
                else:
                    url = f"http://{subdomain}:{port}" if port != 80 else f"http://{subdomain}"
                response = requests.head(url, timeout=5, allow_redirects=True, verify=False)
                if response.status_code < 500:
                    scan_data['open_ports'].append(port)
                    scan_data['services'][str(port)] = {
                        'name': service,
                        'product': f"HTTP server (status: {response.status_code})",
                        'version': response.headers.get('Server', ''),
                        'state': 'open'
                    }
            except Exception:
                pass
        if not scan_data['ip_address']:
            try:
                ip = socket.gethostbyname(subdomain)
                scan_data['ip_address'] = ip
            except Exception:
                scan_data['ip_address'] = 'unknown'
        if scan_data['open_ports']:
            scan_data['is_active'] = 'up'
    return scan_data

def scan_subdomain_vulnerabilities(subdomain):
    """Scan subdomain for vulnerabilities using nmap vuln scripts. Only store if output indicates a real finding."""
    vulnerabilities = []
    try:
        nm = nmap.PortScanner()
        vuln_result = nm.scan(subdomain, arguments="-sT --top-ports 100 --script vuln")
        if vuln_result['scan']:
            for host_ip, host_data in vuln_result['scan'].items():
                if 'tcp' in host_data:
                    for port, port_info in host_data['tcp'].items():
                        scripts = port_info.get('script', {})
                        for script_name, script_output in scripts.items():
                            # Only store if output does not indicate 'no vulnerability found'
                            output_lower = script_output.lower()
                            if not ("couldn't find" in output_lower or "no vulnerabilities found" in output_lower or "not vulnerable" in output_lower):
                                vulnerabilities.append({'port': port, 'nmap_script': script_name})
    except Exception as e:
        print(f"[nmap] Vuln script scan failed: {e}")
    return vulnerabilities
