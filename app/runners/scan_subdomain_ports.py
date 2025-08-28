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
        common_ports = "22,25,53,80,443,587,993,995,3306,5432,8080,8443"
        if nmap_args:
            result = nm.scan(subdomain, common_ports, arguments=nmap_args)
        else:
            result = nm.scan(subdomain, common_ports)
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
        # HTTP fallback
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
