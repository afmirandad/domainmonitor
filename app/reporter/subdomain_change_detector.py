from app.models.subdomains import subdomains_table
from app.config.database import engine
from sqlalchemy import select
from datetime import datetime, timedelta

def has_new_subdomains(since_minutes=10):
    """
    Returns True if there are subdomains discovered in the last N minutes.
    """
    since = datetime.utcnow() - timedelta(minutes=since_minutes)
    with engine.connect() as conn:
        recent = conn.execute(
            select(subdomains_table.c.id)
            .where(subdomains_table.c.discoverydate >= since)
        ).fetchone()
        return recent is not None

def get_new_subdomains(since_minutes=10):
    """
    Returns a list of subdomains discovered in the last N minutes.
    """
    since = datetime.utcnow() - timedelta(minutes=since_minutes)
    with engine.connect() as conn:
        rows = conn.execute(
            select(subdomains_table.c.subdomain)
            .where(subdomains_table.c.discoverydate >= since)
        ).fetchall()
        return [row[0] for row in rows]
