from app.models.subdomains import subdomains_table, ensure_subdomains_table
from app.models.ports import ports_table, ensure_ports_table
from app.runners.scan_subdomain_ports import scan_subdomain_ports
from app.config.database import engine
from app.config.settings import logger
from sqlalchemy import select, insert, update
from datetime import datetime

class PortEnumerationService:
    @staticmethod
    def enumerate_and_store_ports_for_subdomains_ondemand(new_subdomains):
        """Scan and store ports for a provided list of subdomains."""
        if not new_subdomains:
            logger.info("No subdomains provided for on-demand port scan.")
            return
        from app.runners.scan_subdomain_ports import scan_subdomain_ports, scan_subdomain_vulnerabilities
        from app.models.vulnerabilities import vulnerabilities_table, ensure_vulnerabilities_table
        ensure_subdomains_table()
        ensure_ports_table()
        ensure_vulnerabilities_table()
        with engine.connect() as conn:
            for subdomain in new_subdomains:
                logger.info(f"[On-demand] Scanning ports for subdomain: {subdomain}")
                scan_data = scan_subdomain_ports(subdomain)
                open_ports = set(scan_data.get('open_ports', []))
                services = scan_data.get('services', {})
                existing_ports = conn.execute(select(ports_table.c.port, ports_table.c.status, ports_table.c.id).where(ports_table.c.subdomain == subdomain)).fetchall()
                existing_ports_dict = {p[0]: (p[1], p[2]) for p in existing_ports}
                for port in open_ports:
                    service_info = services.get(str(port), {})
                    service_name = service_info.get('name', '')
                    port_id = None
                    if port not in existing_ports_dict:
                        stmt = insert(ports_table).values(
                            subdomain=subdomain,
                            discoverydate=datetime.utcnow(),
                            port=port,
                            status='open',
                            service=service_name
                        )
                        result = conn.execute(stmt)
                        conn.commit()
                        port_id = result.inserted_primary_key[0] if result.inserted_primary_key else None
                    else:
                        prev_status, port_id = existing_ports_dict[port]
                        if prev_status != 'open':
                            upd = update(ports_table).where(
                                ports_table.c.subdomain == subdomain,
                                ports_table.c.port == port
                            ).values(status='open', discoverydate=datetime.utcnow(), service=service_name)
                            conn.execute(upd)
                            conn.commit()
                    if port_id:
                        vulns = scan_subdomain_vulnerabilities(subdomain)
                        for vuln in vulns:
                            if vuln['port'] == port:
                                stmt_vuln = insert(vulnerabilities_table).values(
                                    port_id=port_id,
                                    vuln_id=vuln['nmap_script'],
                                    title=vuln['nmap_script']
                                )
                                conn.execute(stmt_vuln)
                                conn.commit()
                for port, (prev_status, port_id) in existing_ports_dict.items():
                    if port not in open_ports and prev_status != 'closed':
                        upd = update(ports_table).where(
                            ports_table.c.subdomain == subdomain,
                            ports_table.c.port == port
                        ).values(status='closed', discoverydate=datetime.utcnow())
                        conn.execute(upd)
                        conn.commit()

    @staticmethod
    def enumerate_and_store_ports():
        ensure_subdomains_table()
        ensure_ports_table()
        from app.runners.scan_subdomain_ports import scan_subdomain_ports, scan_subdomain_vulnerabilities
        from app.models.vulnerabilities import vulnerabilities_table, ensure_vulnerabilities_table
        ensure_subdomains_table()
        ensure_ports_table()
        ensure_vulnerabilities_table()
        with engine.connect() as conn:
            # Get all active subdomains
            subs = conn.execute(select(subdomains_table.c.subdomain).where(subdomains_table.c.active == True)).fetchall()
            for row in subs:
                subdomain = row[0]
                logger.info(f"Scanning ports for subdomain: {subdomain}")
                scan_data = scan_subdomain_ports(subdomain)
                open_ports = set(scan_data.get('open_ports', []))
                services = scan_data.get('services', {})
                # Query already registered ports for this subdomain
                existing_ports = conn.execute(select(ports_table.c.port, ports_table.c.status, ports_table.c.id).where(ports_table.c.subdomain == subdomain)).fetchall()
                existing_ports_dict = {p[0]: (p[1], p[2]) for p in existing_ports}  # port: (status, id)
                # Insert or update open ports
                for port in open_ports:
                    service_info = services.get(str(port), {})
                    service_name = service_info.get('name', '')
                    port_id = None
                    if port not in existing_ports_dict:
                        stmt = insert(ports_table).values(
                            subdomain=subdomain,
                            discoverydate=datetime.utcnow(),
                            port=port,
                            status='open',
                            service=service_name
                        )
                        result = conn.execute(stmt)
                        conn.commit()
                        port_id = result.inserted_primary_key[0] if result.inserted_primary_key else None
                    else:
                        prev_status, port_id = existing_ports_dict[port]
                        if prev_status != 'open':
                            upd = update(ports_table).where(
                                ports_table.c.subdomain == subdomain,
                                ports_table.c.port == port
                            ).values(status='open', discoverydate=datetime.utcnow(), service=service_name)
                            conn.execute(upd)
                            conn.commit()
                    # Scan and store vulnerabilities for this port
                    if port_id:
                        vulns = scan_subdomain_vulnerabilities(subdomain)
                        for vuln in vulns:
                            if vuln['port'] == port:
                                stmt_vuln = insert(vulnerabilities_table).values(
                                    port_id=port_id,
                                    vuln_id=vuln['nmap_script'],
                                    title=vuln['nmap_script']
                                )
                                conn.execute(stmt_vuln)
                                conn.commit()
                # Mark as closed the ports that are no longer open
                for port, (prev_status, port_id) in existing_ports_dict.items():
                    if port not in open_ports and prev_status != 'closed':
                        upd = update(ports_table).where(
                            ports_table.c.subdomain == subdomain,
                            ports_table.c.port == port
                        ).values(status='closed', discoverydate=datetime.utcnow())
                        conn.execute(upd)
                        conn.commit()
