from sqlalchemy import Table, Column, Integer, String, DateTime, Boolean, MetaData
from app.config.database import engine
from datetime import datetime

metadata = MetaData()

subdomains_table = Table(
    'subdomains', metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('domain', String(255), nullable=False),
    Column('subdomain', String(255), nullable=False),
    Column('discoverydate', DateTime, nullable=False, default=datetime.utcnow),
    Column('active', Boolean, nullable=False, default=True)
)

def ensure_subdomains_table():
    metadata.create_all(engine, tables=[subdomains_table])
