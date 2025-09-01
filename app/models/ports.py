from sqlalchemy import Table, Column, Integer, String, DateTime, MetaData
from app.config.database import engine
from datetime import datetime

metadata = MetaData()

ports_table = Table(
    'ports', metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('subdomain', String(255), nullable=False),
    Column('discoverydate', DateTime, nullable=False, default=datetime.utcnow),
    Column('port', Integer, nullable=False),
    Column('status', String(16), nullable=False),  # open/closed
    Column('service', String(255), nullable=True)
)

def ensure_ports_table():
    metadata.create_all(engine, tables=[ports_table])
