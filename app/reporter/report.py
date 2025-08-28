
from app.config.settings import logger
import pandas as pd


def display_scan_results(scan_results):
    """
    Display port scan results in a formatted way
    """
    rows = []
    for subdomain, scan_data in scan_results:
        try:
            domain = scan_data.get('domain', '-')
            detected_at = scan_data.get('detected_at', '-')
            last_scanned = scan_data.get('last_scanned', '-')
            if hasattr(detected_at, 'strftime'):
                detected_at = detected_at.strftime('%Y-%m-%d %H:%M')
            if hasattr(last_scanned, 'strftime'):
                last_scanned = last_scanned.strftime('%Y-%m-%d %H:%M')
            ip_address = scan_data.get('ip_address', '-')
            is_active = scan_data.get('is_active', '-')
            open_ports = scan_data.get('open_ports', [])
            services_desc = scan_data.get('services_desc', '-')
            port_state = scan_data.get('port_state', '-')
            # If services_desc is a dict, use per-port info
            services = scan_data.get('services', {})
            if isinstance(open_ports, list) and open_ports:
                for port in open_ports:
                    # Try to get service description and state per port
                    if isinstance(services, dict) and str(port) in services:
                        service_info = services[str(port)]
                        desc = service_info.get('name', '-')
                        state = service_info.get('state', '-')
                    else:
                        desc = services_desc if services_desc != '-' else '-'
                        state = port_state if port_state != '-' else '-'
                    rows.append({
                        'domain': domain,
                        'subdomain': subdomain,
                        'detected_at': detected_at,
                        'ip_address': ip_address,
                        'is_active': is_active,
                        'port': port,
                        'service_desc': desc,
                        'port_state': state,
                        'last_scanned': last_scanned
                    })
            else:
                rows.append({
                    'domain': domain,
                    'subdomain': subdomain,
                    'detected_at': detected_at,
                    'ip_address': ip_address,
                    'is_active': is_active,
                    'port': '-',
                    'service_desc': services_desc,
                    'port_state': port_state,
                    'last_scanned': last_scanned
                })
        except Exception as e:
            logger.error(f"Error processing scan result for {subdomain}: {e}")
            rows.append({
                'domain': '-',
                'subdomain': subdomain,
                'detected_at': '-',
                'ip_address': '-',
                'is_active': '-',
                'port': '-',
                'service_desc': 'ERROR',
                'port_state': 'ERROR',
                'last_scanned': '-'
            })

    try:
        df = pd.DataFrame(rows, columns=[
            'domain', 'subdomain', 'detected_at', 'ip_address', 'is_active',
            'port', 'service_desc', 'port_state', 'last_scanned'])
        print(df.to_markdown(index=False))
    except Exception as e:
        logger.error(f"Error displaying results table: {e}")
