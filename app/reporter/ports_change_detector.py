from app.models.ports import ports_table
from app.config.database import engine
from sqlalchemy import select
from datetime import datetime, timedelta

def has_new_or_changed_ports(since_minutes=10):
    """
    Returns True if there are ports discovered or updated in the last N minutes.
    """
    since = datetime.utcnow() - timedelta(minutes=since_minutes)
    with engine.connect() as conn:
        recent = conn.execute(
            select(ports_table.c.id)
            .where(ports_table.c.discoverydate >= since)
        ).fetchone()
        return recent is not None
