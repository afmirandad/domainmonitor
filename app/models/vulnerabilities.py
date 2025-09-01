from sqlalchemy import Table, Column, Integer, String, DECIMAL, Text, ForeignKey, MetaData
from app.config.database import engine

metadata = MetaData()

vulnerabilities_table = Table(
    'vulnerabilities', metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('port_id', Integer, ForeignKey('ports.id'), nullable=False),
    Column('vuln_id', String(64), nullable=False),
    Column('title', String(255), nullable=False),
    Column('cvss_score', DECIMAL(3,1), nullable=True),
    Column('description', Text, nullable=True),
    Column('nmap_script', String(128), nullable=True),
    Column('reference', String(255), nullable=True)
)

def ensure_vulnerabilities_table():
    # Crea la tabla si no existe
    metadata.create_all(engine, tables=[vulnerabilities_table])
