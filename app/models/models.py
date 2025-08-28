from sqlalchemy import Table, Column, Integer, String, DateTime, Text
from datetime import datetime, UTC
from app.config.database import metadata

subdomains_table = Table(
    'subdomains', metadata,
    Column('id', Integer, primary_key=True),
    Column('domain', String(255)),
    Column('subdomain', String(255)),
    Column('detected_at', DateTime, default=datetime.now(UTC)),
    Column('ip_address', String(45)),
    Column('is_active', String(10)),
    Column('open_ports', Text),
    Column('services', Text),
    Column('last_scanned', DateTime)
)

__all__ = ["subdomains_table"]
