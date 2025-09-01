from app.models.subdomains import subdomains_table, ensure_subdomains_table
from app.runners.hackertarget import fetch_hackertarget_subdomains
from app.runners.rapiddns import fetch_rapiddns_subdomains
from app.runners.certspotter import fetch_certspotter_subdomains
from app.runners.crtsh import fetch_crtsh_subdomains
from app.runners.validate_subdomains import validate_subdomains
from app.config.settings import logger, DOMAINS_ENV
from app.config.database import engine
from sqlalchemy import select, insert
from datetime import datetime

class SubdomainEnumerationService:
    @staticmethod
    def enumerate_and_store():
        ensure_subdomains_table()
        domains = []
        if DOMAINS_ENV:
            domains = [d.strip() for d in DOMAINS_ENV.split(',') if d.strip()]
        if not domains:
            logger.error("No domains found in DOMAINS_ENV.")
            return
        for domain in domains:
            logger.info(f"Enumerating subdomains for domain: {domain}")
            hackertarget_subs = fetch_hackertarget_subdomains(domain) or []
            rapiddns_subs = fetch_rapiddns_subdomains(domain) or []
            certspotter_subs = fetch_certspotter_subdomains(domain) or []
            crtsh_subs = fetch_crtsh_subdomains(domain) or []
            all_subs = set(hackertarget_subs + rapiddns_subs + certspotter_subs + crtsh_subs)
            if not all_subs:
                logger.warning(f"No subdomains found for {domain} from any source.")
                continue
            # Filtrar subdominios con espacios y limpiar puntos finales
            cleaned_subs = set()
            for sub in validate_subdomains(list(all_subs)):
                sub_clean = sub.strip().rstrip('.')
                if ' ' in sub_clean or not sub_clean:
                    continue
                cleaned_subs.add(sub_clean)
            logger.info(f"Valid subdomains for {domain}: {cleaned_subs}")
            with engine.connect() as conn:
                for sub in cleaned_subs:
                    # Evitar duplicados con y sin punto final
                    sel = select(subdomains_table.c.id).where(
                        subdomains_table.c.domain == domain,
                        (subdomains_table.c.subdomain == sub) | (subdomains_table.c.subdomain == sub + '.')
                    )
                    result = conn.execute(sel).fetchone()
                    if not result:
                        stmt = insert(subdomains_table).values(
                            domain=domain,
                            subdomain=sub,
                            discoverydate=datetime.utcnow(),
                            active=True
                        )
                        conn.execute(stmt)
                        conn.commit()
