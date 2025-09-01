from app.models.subdomains import subdomains_table, ensure_subdomains_table
from app.models.ports import ports_table, ensure_ports_table
from app.runners.scan_subdomain_ports import scan_subdomain_ports
from app.config.database import engine
from app.config.settings import logger
from sqlalchemy import select, insert, update
from datetime import datetime

class PortEnumerationService:
    @staticmethod
    def enumerate_and_store_ports():
        ensure_subdomains_table()
        ensure_ports_table()
        with engine.connect() as conn:
            # Obtener todos los subdominios activos
            subs = conn.execute(select(subdomains_table.c.subdomain).where(subdomains_table.c.active == True)).fetchall()
            for row in subs:
                subdomain = row[0]
                logger.info(f"Scanning ports for subdomain: {subdomain}")
                scan_data = scan_subdomain_ports(subdomain)
                open_ports = set(scan_data.get('open_ports', []))
                services = scan_data.get('services', {})
                # Consultar puertos ya registrados para este subdominio
                existing_ports = conn.execute(select(ports_table.c.port, ports_table.c.status).where(ports_table.c.subdomain == subdomain)).fetchall()
                existing_ports_dict = {p[0]: p[1] for p in existing_ports}
                # Insertar o actualizar puertos abiertos
                for port in open_ports:
                    service_info = services.get(str(port), {})
                    service_name = service_info.get('name', '')
                    if port not in existing_ports_dict:
                        stmt = insert(ports_table).values(
                            subdomain=subdomain,
                            discoverydate=datetime.utcnow(),
                            port=port,
                            status='open',
                            service=service_name
                        )
                        conn.execute(stmt)
                        conn.commit()
                    elif existing_ports_dict[port] != 'open':
                        upd = update(ports_table).where(
                            ports_table.c.subdomain == subdomain,
                            ports_table.c.port == port
                        ).values(status='open', discoverydate=datetime.utcnow(), service=service_name)
                        conn.execute(upd)
                        conn.commit()
                # Marcar como cerrados los puertos que ya no están abiertos
                for port, prev_status in existing_ports_dict.items():
                    if port not in open_ports and prev_status != 'closed':
                        upd = update(ports_table).where(
                            ports_table.c.subdomain == subdomain,
                            ports_table.c.port == port
                        ).values(status='closed', discoverydate=datetime.utcnow())
                        conn.execute(upd)
                        conn.commit()
