from app.config.database import engine
from app.models.subdomains import subdomains_table
from app.models.ports import ports_table
from sqlalchemy import select, join
import pandas as pd

def get_ports_report_df():
    j = join(ports_table, subdomains_table, ports_table.c.subdomain == subdomains_table.c.subdomain)
    stmt = select(
        subdomains_table.c.subdomain,
        ports_table.c.discoverydate,
        ports_table.c.port,
        ports_table.c.service
    ).select_from(j)
    with engine.connect() as conn:
        rows = conn.execute(stmt).fetchall()
    df = pd.DataFrame(rows, columns=['Subdomain', 'Discovery Date', 'Port', 'Service'])
    # Agrupar por subdominio y discoverydate, concatenar puertos y servicios
    if not df.empty:
        grouped = df.groupby(['Subdomain']).agg({
            'Port': lambda x: ', '.join(map(str, sorted(set(x)))),
            'Service': lambda x: ', '.join(sorted(set(x)))
        }).reset_index()
        return grouped[['Subdomain', 'Port', 'Service']]
    return df[['Subdomain', 'Port', 'Service']]

def get_ports_report_text():
    df = get_ports_report_df()
    if df.empty:
        return 'No data found.'
    # Encabezado markdown
    lines = ["| Subdomain | Ports | Services |", "|-----------|-------|----------|"]
    for i, row in df.iterrows():
        if i >= 10:
            lines.append(f"| ...and {len(df)-10} more | | |")
            break
        lines.append(f"| {row['Subdomain']} | {row['Port']} | {row['Service']} |")
    return '\n'.join(lines)