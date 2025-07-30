# entrypoint.py
import os
import pymysql
pymysql.install_as_MySQLdb()
import sys
import logging
import requests
import subprocess
import dns.resolver
from datetime import datetime, UTC
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, DateTime, insert, select
from email_notifier import EmailNotifier

# Logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Env vars
MYSQL_URL = os.getenv("DATABASE_URL")
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASSWORD")
EMAIL_TO = os.getenv("EMAIL_TO")
DOMAINS_ENV = os.getenv("DOMAINS")

# DB setup
engine = create_engine(MYSQL_URL)
metadata = MetaData()
subdomains_table = Table(
    'subdomains', metadata,
    Column('id', Integer, primary_key=True),
    Column('domain', String(255)),
    Column('subdomain', String(255)),
    Column('detected_at', DateTime, default=datetime.now(UTC))
)
metadata.create_all(engine)

def fetch_subdomains(domain):
    logger.info(f"Fetching subdomains for: {domain}")
    subdomains = set()

    try:
        result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True)
        subdomains.update(result.stdout.lower().splitlines())
    except Exception as e:
        logger.warning(f"subfinder failed: {e}")

    try:
        res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        for line in res.text.strip().splitlines():
            sub, _ = line.split(",")
            subdomains.add(sub.lower())
    except Exception as e:
        logger.warning(f"Hackertarget request failed: {e}")

    try:
        res = requests.get(f"https://rapiddns.io/subdomain/{domain}?plain=1")
        subdomains.update(res.text.lower().splitlines())
    except Exception as e:
        logger.warning(f"RapidDNS request failed: {e}")

    try:
        res = requests.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names")
        for cert in res.json():
            subdomains.update(
                name.lower() for name in cert.get("dns_names", []) if name.endswith(f".{domain}")
            )
    except Exception as e:
        logger.warning(f"CertSpotter request failed: {e}")

    try:
        res = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        names = [item["name_value"].lower() for item in res.json()]
        for name in names:
            subdomains.update(name.split('\n'))
    except Exception as e:
        logger.warning(f"crt.sh request failed: {e}")

    return sorted(s for s in subdomains if s.endswith(f".{domain}"))

def validate_subdomains(subdomains):
    active = []
    resolver = dns.resolver.Resolver()
    for sub in subdomains:
        try:
            resolver.resolve(sub, "A")
            active.append(sub)
        except:
            pass
    return active

def get_existing_subdomains(domain):
    with engine.connect() as conn:
        result = conn.execute(select(subdomains_table.c.subdomain).where(subdomains_table.c.domain == domain))
        return set(row[0] for row in result.fetchall())

def save_new_subdomains(domain, subdomains):
    with engine.connect() as conn:
        for sub in subdomains:
            stmt = insert(subdomains_table).values(domain=domain, subdomain=sub, detected_at=datetime.utcnow())
            conn.execute(stmt)
        conn.commit()

def main():
    if not DOMAINS_ENV:
        logger.error("DOMAINS environment variable not set")
        sys.exit(1)

    domains = [d.strip() for d in DOMAINS_ENV.strip("{} ").split(",") if d.strip()]
    if not domains:
        logger.error("No valid domains provided")
        sys.exit(1)

    notifier = EmailNotifier(EMAIL_USER, EMAIL_PASS, EMAIL_TO)

    for domain in domains:
        all_subs = fetch_subdomains(domain)
        active_subs = validate_subdomains(all_subs)
        logger.info(f"{len(active_subs)} active subdomains for {domain}")

        existing = get_existing_subdomains(domain)
        new_subs = sorted(set(active_subs) - existing)

        if new_subs:
            logger.info(f"{len(new_subs)} new subdomains detected for {domain}")
            save_new_subdomains(domain, new_subs)
            notifier.send(domain, new_subs)
        else:
            logger.info(f"No new subdomains for {domain}")

if __name__ == "__main__":
    main()
