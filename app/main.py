

from app.config.settings import logger, MYSQL_URL, EMAIL_USER, EMAIL_PASS, EMAIL_TO, DOMAINS_ENV, TEAMS_WEBHOOK_URL
from app.runners.hackertarget import fetch_hackertarget_subdomains
from app.runners.rapiddns import fetch_rapiddns_subdomains
from app.runners.certspotter import fetch_certspotter_subdomains
from app.runners.crtsh import fetch_crtsh_subdomains
from app.runners.validate_subdomains import validate_subdomains
from app.runners.scan_subdomain_ports import scan_subdomain_ports
from app.reporter.report import display_scan_results
from app.config.database import engine,ensure_database_schema
from app.models.models import subdomains_table
from sqlalchemy import insert
from datetime import datetime, UTC

def log_section(title):
    logger.info("\n" + "="*60)
    logger.info(title)
    logger.info("="*60)

def main():
    # Ensure the database schema exists before any inserts
    ensure_database_schema()
    # Parse domains from environment variable
    domains = []
    if DOMAINS_ENV:
        domains = [d.strip() for d in DOMAINS_ENV.split(',') if d.strip()]
    if not domains:
        logger.error("No domains found in DOMAINS_ENV.")
        return

    for domain in domains:
        log_section(f"Testing all runners with domain: {domain}")

        # Fetch subdomains from all sources
        hackertarget_subs = fetch_hackertarget_subdomains(domain)
        rapiddns_subs = fetch_rapiddns_subdomains(domain)
        certspotter_subs = fetch_certspotter_subdomains(domain)
        crtsh_subs = fetch_crtsh_subdomains(domain)

        # Combine and validate
        all_subs = set(hackertarget_subs + rapiddns_subs + certspotter_subs + crtsh_subs)
        valid_subs = validate_subdomains(list(all_subs))


        # Check for new subdomains and port changes
        from sqlalchemy import select
        new_subs = []
        changed_subs = []
        with engine.connect() as conn:
            # Get existing subdomains and their open_ports for this domain
            existing = {}
            result = conn.execute(select(subdomains_table.c.subdomain, subdomains_table.c.open_ports).where(subdomains_table.c.domain == domain))
            for row in result.fetchall():
                existing[row[0]] = set(row[1].split(",")) if row[1] else set()

        # Determine which subdomains are new or have port changes
        for sub in valid_subs:
            if sub not in existing:
                new_subs.append(sub)
            else:
                # Check for port changes
                scan_data = scan_subdomain_ports(sub)
                current_ports = set(map(str, scan_data.get('open_ports', [])))
                if current_ports != existing[sub]:
                    changed_subs.append((sub, scan_data))

        # Only scan and insert if there are new subdomains or port changes
        scan_results = []
        # Scan new subdomains
        for sub in new_subs:
            scan_data = scan_subdomain_ports(sub)
            if isinstance(scan_data, dict):
                scan_data['domain'] = domain
            scan_results.append((sub, scan_data))
        # Add changed subdomains
        for sub, scan_data in changed_subs:
            if isinstance(scan_data, dict):
                scan_data['domain'] = domain
            scan_results.append((sub, scan_data))

        if scan_results:
            from sqlalchemy import select, update
            with engine.connect() as conn:
                for sub, scan_data in scan_results:
                    try:
                        domain_val = scan_data.get('domain', domain)
                        detected_at = scan_data.get('detected_at', datetime.now(UTC))
                        ip_address = scan_data.get('ip_address', '')
                        is_active = scan_data.get('is_active', '')
                        last_scanned = scan_data.get('last_scanned', datetime.now(UTC))
                        services = scan_data.get('services', {})
                        open_ports = scan_data.get('open_ports', [])
                        if isinstance(open_ports, list) and open_ports:
                            for port in open_ports:
                                port_str = str(port)
                                # Check for duplicate
                                sel = select(subdomains_table.c.id).where(
                                    subdomains_table.c.domain == domain_val,
                                    subdomains_table.c.subdomain == sub,
                                    subdomains_table.c.open_ports == port_str
                                )
                                result = conn.execute(sel).fetchone()
                                if result:
                                    # Update detected_at and last_scanned
                                    upd = update(subdomains_table).where(
                                        subdomains_table.c.id == result[0]
                                    ).values(
                                        detected_at=detected_at,
                                        last_scanned=last_scanned
                                    )
                                    conn.execute(upd)
                                    conn.commit()
                                else:
                                    if isinstance(services, dict) and port_str in services:
                                        service_info = services[port_str]
                                        service_desc = service_info.get('name', '')
                                        port_state = service_info.get('state', '')
                                    else:
                                        service_desc = scan_data.get('services_desc', '')
                                        port_state = scan_data.get('port_state', '')
                                    stmt = insert(subdomains_table).values(
                                        domain=domain_val,
                                        subdomain=sub,
                                        detected_at=detected_at,
                                        ip_address=ip_address,
                                        is_active=is_active,
                                        open_ports=port_str,
                                        services_desc=service_desc,
                                        port_state=port_state,
                                        last_scanned=last_scanned
                                    )
                                    conn.execute(stmt)
                                    conn.commit()
                        else:
                            # No open ports, check for duplicate
                            sel = select(subdomains_table.c.id).where(
                                subdomains_table.c.domain == domain_val,
                                subdomains_table.c.subdomain == sub,
                                subdomains_table.c.open_ports == ''
                            )
                            result = conn.execute(sel).fetchone()
                            if result:
                                upd = update(subdomains_table).where(
                                    subdomains_table.c.id == result[0]
                                ).values(
                                    detected_at=detected_at,
                                    last_scanned=last_scanned
                                )
                                conn.execute(upd)
                                conn.commit()
                            else:
                                stmt = insert(subdomains_table).values(
                                    domain=domain_val,
                                    subdomain=sub,
                                    detected_at=detected_at,
                                    ip_address=ip_address,
                                    is_active=is_active,
                                    open_ports='',
                                    services_desc=scan_data.get('services_desc', ''),
                                    port_state=scan_data.get('port_state', ''),
                                    last_scanned=last_scanned
                                )
                                conn.execute(stmt)
                                conn.commit()
                    except Exception as e:
                        logger.error(f"Error inserting/updating {sub} in database: {e}")

            # Show results using the reporting module
            display_scan_results(scan_results)
        else:
            logger.info(f"No new subdomains or port changes for {domain}. Skipping scan and insert.")

if __name__ == "__main__":
    logger.info("App started!")
    logger.info(f"MYSQL_URL: {MYSQL_URL}")
    logger.info(f"EMAIL_USER: {EMAIL_USER}")
    logger.info(f"EMAIL_TO: {EMAIL_TO}")
    logger.info(f"DOMAINS_ENV: {DOMAINS_ENV}")
    #logger.info(f"TEAMS_WEBHOOK_URL: {TEAMS_WEBHOOK_URL}")
    main()
