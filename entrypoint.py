# entrypoint.py
import os
import pymysql
pymysql.install_as_MySQLdb()
import sys
import logging
import requests
import subprocess
import dns.resolver
import nmap
import socket
import urllib3
from datetime import datetime, UTC
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, DateTime, insert, select, Text, text
from email_notifier import EmailNotifier
from app.reporter.report import display_scan_results

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✅ .env file loaded successfully")
except ImportError:
    print("⚠️ python-dotenv not installed, using system environment variables only")
except Exception as e:
    print(f"⚠️ Could not load .env file: {e}")

# Disable SSL warnings for the HTTP fallback checks
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

try:
    from teams_notifier import TeamsNotifier
    TEAMS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"⚠️ Teams notifier not available: {e}")
    TeamsNotifier = None
    TEAMS_AVAILABLE = False

# Force flush stdout/stderr for Railway
import sys
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# Env vars
MYSQL_URL = os.getenv("DATABASE_URL")
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASSWORD")
EMAIL_TO = os.getenv("EMAIL_TO")
DOMAINS_ENV = os.getenv("DOMAINS")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL")

# DB setup
engine = create_engine(MYSQL_URL)
metadata = MetaData()
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

def ensure_database_schema():
    """Ensure the database schema is up to date with all required columns"""
    logger.info("🔧 Checking and updating database schema...")
    
    try:
        with engine.connect() as conn:
            # Check if new columns exist and add them if they don't
            columns_to_add = [
                ('ip_address', 'VARCHAR(45)'),
                ('is_active', 'VARCHAR(10)'),
                ('open_ports', 'TEXT'),
                ('services', 'TEXT'),
                ('last_scanned', 'DATETIME')
            ]
            
            for column_name, column_type in columns_to_add:
                try:
                    # Try to add the column
                    alter_sql = f"ALTER TABLE subdomains ADD COLUMN {column_name} {column_type}"
                    conn.execute(text(alter_sql))
                    conn.commit()
                    logger.info(f"✅ Added column: {column_name}")
                except Exception as e:
                    if "Duplicate column name" in str(e) or "already exists" in str(e):
                        logger.info(f"ℹ️ Column {column_name} already exists")
                    else:
                        logger.warning(f"⚠️ Could not add column {column_name}: {e}")
            
            logger.info("✅ Database schema check completed")
            
    except Exception as e:
        logger.error(f"❌ Database schema update failed: {e}")
        # Continue anyway - the table creation below will handle it
    
    # Create tables (this will create the table if it doesn't exist)
    metadata.create_all(engine)

def fetch_subdomains(domain):
    logger.info(f"🔍 Fetching subdomains for: {domain}")
    subdomains = set()
    sources_tried = 0
    sources_successful = 0

    # Subfinder
    sources_tried += 1
    logger.info(f"📡 [1/5] Trying Subfinder...")
    try:
        result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True, timeout=60)
        found_subs = result.stdout.lower().splitlines()
        subdomains.update(found_subs)
        sources_successful += 1
        logger.info(f"✅ Subfinder found {len(found_subs)} subdomains")
    except subprocess.TimeoutExpired:
        logger.warning(f"⏰ Subfinder timeout after 60 seconds")
    except Exception as e:
        logger.warning(f"❌ Subfinder failed: {e}")

    # HackerTarget
    sources_tried += 1
    logger.info(f"📡 [2/5] Trying HackerTarget API...")
    try:
        res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=30)
        found_subs = []
        for line in res.text.strip().splitlines():
            if ',' in line:
                sub, _ = line.split(",", 1)
                found_subs.append(sub.lower())
        subdomains.update(found_subs)
        sources_successful += 1
        logger.info(f"✅ HackerTarget found {len(found_subs)} subdomains")
    except Exception as e:
        logger.warning(f"❌ HackerTarget request failed: {e}")

    # RapidDNS
    sources_tried += 1
    logger.info(f"📡 [3/5] Trying RapidDNS...")
    try:
        res = requests.get(f"https://rapiddns.io/subdomain/{domain}?plain=1", timeout=30)
        found_subs = res.text.lower().splitlines()
        subdomains.update(found_subs)
        sources_successful += 1
        logger.info(f"✅ RapidDNS found {len(found_subs)} subdomains")
    except Exception as e:
        logger.warning(f"❌ RapidDNS request failed: {e}")

    # CertSpotter
    sources_tried += 1
    logger.info(f"📡 [4/5] Trying CertSpotter API...")
    try:
        res = requests.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names", timeout=30)
        found_subs = []
        for cert in res.json():
            for name in cert.get("dns_names", []):
                if name.lower().endswith(f".{domain}"):
                    found_subs.append(name.lower())
        subdomains.update(found_subs)
        sources_successful += 1
        logger.info(f"✅ CertSpotter found {len(found_subs)} subdomains")
    except Exception as e:
        logger.warning(f"❌ CertSpotter request failed: {e}")

    # crt.sh
    sources_tried += 1
    logger.info(f"📡 [5/5] Trying crt.sh...")
    try:
        res = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        found_subs = []
        names = [item["name_value"].lower() for item in res.json()]
        for name in names:
            for sub in name.split('\n'):
                if sub.endswith(f".{domain}"):
                    found_subs.append(sub)
        subdomains.update(found_subs)
        sources_successful += 1
        logger.info(f"✅ crt.sh found {len(found_subs)} subdomains")
    except Exception as e:
        logger.warning(f"❌ crt.sh request failed: {e}")

    final_subs = sorted(s for s in subdomains if s.endswith(f".{domain}"))
    logger.info(f"📊 Summary: {sources_successful}/{sources_tried} sources successful, {len(final_subs)} unique subdomains found")
    
    return final_subs

def validate_subdomains(subdomains):
    logger.info(f"🧪 Validating {len(subdomains)} subdomains via DNS resolution...")
    active = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    
    for i, sub in enumerate(subdomains, 1):
        try:
            resolver.resolve(sub, "A")
            active.append(sub)
            if i % 10 == 0 or i == len(subdomains):
                logger.info(f"  Progress: {i}/{len(subdomains)} checked, {len(active)} active")
        except:
            pass
    
    logger.info(f"✅ DNS validation complete: {len(active)}/{len(subdomains)} subdomains are active")
    return active

def get_nmap_arguments():
    """Detect which nmap arguments work in current environment"""
    nm = nmap.PortScanner()
    
    # Test different argument combinations in order of preference
    argument_sets = [
        '-sT -T4 --max-retries 2 --host-timeout 60s',  # Full options
        '-sT -T4 --max-retries 2',                      # Without timeout
        '-sT -T4',                                      # Basic fast
        '-sT',                                          # Just TCP connect
        ''                                              # Default (last resort)
    ]
    
    for args in argument_sets:
        try:
            # Test on localhost
            nm.scan('127.0.0.1', '80', arguments=args)
            logger.info(f"✅ Nmap arguments working: '{args}'" if args else "✅ Default nmap scan working")
            return args
        except Exception as e:
            logger.debug(f"❌ Nmap args '{args}' failed: {e}")
            continue
    
    logger.warning("⚠️ No nmap arguments worked, using minimal scan")
    return ''

def check_http_ports(subdomain):
    """
    Check common HTTP/HTTPS ports directly using requests
    This is a fallback when nmap doesn't work properly
    """
    http_results = {
        'ports_found': [],
        'services': {}
    }
    
    # Test common web ports
    test_ports = [
        (80, 'http'),
        (443, 'https'),
        (8080, 'http-alt'),
        (8443, 'https-alt')
    ]
    
    for port, service in test_ports:
        try:
            if port == 443 or port == 8443:
                url = f"https://{subdomain}:{port}" if port != 443 else f"https://{subdomain}"
            else:
                url = f"http://{subdomain}:{port}" if port != 80 else f"http://{subdomain}"
            
            # Quick connection test
            response = requests.head(url, timeout=5, allow_redirects=True, verify=False)
            if response.status_code < 500:  # Any response indicates the port is open
                http_results['ports_found'].append(port)
                http_results['services'][str(port)] = {
                    'name': service,
                    'product': f"HTTP server (status: {response.status_code})",
                    'version': response.headers.get('Server', ''),
                    'state': 'open'
                }
                logger.info(f"    🟢 HTTP check: Port {port}/tcp open - {service}")
                
        except requests.exceptions.SSLError:
            # SSL error might still mean the port is open
            if port in [443, 8443]:
                http_results['ports_found'].append(port)
                http_results['services'][str(port)] = {
                    'name': service,
                    'product': 'HTTPS server (SSL/TLS)',
                    'version': '',
                    'state': 'open'
                }
                logger.info(f"    🟢 HTTP check: Port {port}/tcp open - {service} (SSL)")
        except requests.exceptions.ConnectionError:
            # Port is likely closed or filtered
            pass
        except requests.exceptions.Timeout:
            # Port might be open but slow to respond
            pass
        except Exception as e:
            logger.debug(f"    HTTP check error for {subdomain}:{port} - {e}")
    
    return http_results

def scan_subdomain_ports(subdomain, nmap_args=None):
    """
    Scan subdomain for open ports and services using nmap + HTTP fallback
    """
    logger.info(f"🔬 Scanning ports for: {subdomain}")
    
    scan_data = {
        'ip_address': '',
        'is_active': 'no',
        'open_ports': [],
        'services': {}
    }
    
    # Try nmap first
    nmap_found_ports = False
    try:
        nm = nmap.PortScanner()
        
        # Common ports to scan (reduced for faster scanning)
        common_ports = "22,25,53,80,443,587,993,995,3306,5432,8080,8443"
        
        logger.info(f"  🎯 Nmap scanning ports: {common_ports}")
        
        # Use provided arguments or detect them
        if nmap_args is None:
            nmap_args = get_nmap_arguments()
        
        # Perform scan with detected arguments
        if nmap_args:
            logger.debug(f"  Using nmap arguments: {nmap_args}")
            result = nm.scan(subdomain, common_ports, arguments=nmap_args)
        else:
            logger.debug("  Using default nmap scan")
            result = nm.scan(subdomain, common_ports)
        
        # Check if any host was found in scan results
        if result['scan']:
            for host_ip, host_data in result['scan'].items():
                scan_data['ip_address'] = host_ip
                scan_data['is_active'] = host_data['status']['state']
                
                logger.info(f"  📍 Host {host_ip} status: {host_data['status']['state']}")
                
                # Extract open ports and services
                if 'tcp' in host_data:
                    for port, port_info in host_data['tcp'].items():
                        if port_info['state'] == 'open':
                            scan_data['open_ports'].append(port)
                            nmap_found_ports = True
                            
                            service_info = {
                                'name': port_info.get('name', 'unknown'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'state': port_info['state']
                            }
                            scan_data['services'][str(port)] = service_info
                            logger.info(f"    🟢 Nmap: Port {port}/tcp open: {service_info['name']}")
                break  # Use first host found
        else:
            logger.info(f"  🔴 Nmap: No response from {subdomain}")
            
    except Exception as e:
        logger.warning(f"  ❌ Nmap scan failed for {subdomain}: {e}")
    
    # If nmap didn't find ports or failed, try HTTP checks
    if not nmap_found_ports:
        logger.info(f"  🔄 Nmap found no ports, trying HTTP fallback...")
        try:
            http_results = check_http_ports(subdomain)
            
            if http_results['ports_found']:
                # Merge HTTP results with scan data
                scan_data['open_ports'].extend(http_results['ports_found'])
                scan_data['services'].update(http_results['services'])
                scan_data['is_active'] = 'up'
                scan_data['scan_method'] = 'http_fallback'
                
                # Get IP address via DNS lookup if we don't have it
                if not scan_data['ip_address']:
                    try:
                        import socket
                        ip = socket.gethostbyname(subdomain)
                        scan_data['ip_address'] = ip
                        logger.info(f"  📍 Resolved {subdomain} to {ip}")
                    except:
                        scan_data['ip_address'] = 'unknown'
                        
                logger.info(f"  ✅ HTTP fallback found {len(http_results['ports_found'])} open ports")
            else:
                logger.info(f"  🔴 HTTP fallback also found no open ports")
                
        except Exception as http_error:
            logger.warning(f"  ❌ HTTP fallback failed: {http_error}")
    
    # Final scan result summary
    total_ports_found = len(scan_data['open_ports'])
    logger.info(f"  ✅ Total scan completed: {total_ports_found} open ports")
    
    if total_ports_found > 0:
        ports_str = ', '.join(map(str, sorted(scan_data['open_ports'])))
        logger.info(f"    🟢 Open ports: {ports_str}")
    
    return scan_data

def get_existing_subdomains(domain):
    with engine.connect() as conn:
        result = conn.execute(select(subdomains_table.c.subdomain).where(subdomains_table.c.domain == domain))
        return set(row[0] for row in result.fetchall())

def get_existing_scan_data(domain):
    """Get existing scan data for all subdomains of a domain"""
    with engine.connect() as conn:
        try:
            # Try to get all columns including new ones
            result = conn.execute(
                select(
                    subdomains_table.c.subdomain,
                    subdomains_table.c.ip_address,
                    subdomains_table.c.is_active,
                    subdomains_table.c.open_ports,
                    subdomains_table.c.services,
                    subdomains_table.c.last_scanned
                ).where(subdomains_table.c.domain == domain)
            )
            
            existing_data = {}
            for row in result.fetchall():
                subdomain = row[0]
                existing_data[subdomain] = {
                    'ip_address': row[1] or '',
                    'is_active': row[2] or 'unknown',
                    'open_ports': [int(p) for p in row[3].split(',') if p.strip().isdigit()] if row[3] else [],
                    'services': eval(row[4]) if row[4] else {},
                    'last_scanned': row[5]
                }
            return existing_data
            
        except Exception as e:
            if "Unknown column" in str(e):
                # Fallback to basic columns only
                logger.warning("⚠️ New columns not found, using basic subdomain data only")
                result = conn.execute(
                    select(subdomains_table.c.subdomain).where(subdomains_table.c.domain == domain)
                )
                
                existing_data = {}
                for row in result.fetchall():
                    subdomain = row[0]
                    existing_data[subdomain] = {
                        'ip_address': '',
                        'is_active': 'unknown',
                        'open_ports': [],
                        'services': {},
                        'last_scanned': None
                    }
                return existing_data
            else:
                logger.error(f"❌ Error getting existing scan data: {e}")
                return {}

def display_scan_results(scan_results):
    """
    Display port scan results in a formatted way
    """
    logger.info("="*60)
    logger.info("PORT SCAN RESULTS")
    logger.info("="*60)
    
    active_hosts_with_ports = []
    active_hosts_no_ports = []
    inactive_hosts = []
    error_hosts = []
    
    for subdomain, scan_data in scan_results:
        if scan_data.get('error'):
            error_hosts.append((subdomain, scan_data))
        elif scan_data.get('is_active') == 'up':
            if scan_data.get('open_ports'):
                active_hosts_with_ports.append((subdomain, scan_data))
            else:
                active_hosts_no_ports.append((subdomain, scan_data))
        else:
            inactive_hosts.append((subdomain, scan_data))
    
    total_active = len(active_hosts_with_ports) + len(active_hosts_no_ports)
    
    logger.info(f"SUMMARY:")
    logger.info(f"  🟢 Active hosts with open ports: {len(active_hosts_with_ports)}")
    logger.info(f"  🟡 Active hosts (no open ports): {len(active_hosts_no_ports)}")
    logger.info(f"  🔴 Inactive/unreachable hosts: {len(inactive_hosts)}")
    logger.info(f"  ❌ Scan errors: {len(error_hosts)}")
    logger.info(f"  📊 Total active hosts: {total_active}")
    
    if active_hosts_with_ports:
        logger.info("\n🟢 ACTIVE HOSTS WITH OPEN PORTS:")
        logger.info("-" * 40)
        
        for subdomain, scan_data in active_hosts_with_ports:
            ip_addr = scan_data.get('ip_address', 'N/A')
            open_ports = scan_data.get('open_ports', [])
            services = scan_data.get('services', {})
            
            logger.info(f"🟢 {subdomain} ({ip_addr})")
            logger.info(f"   Open ports: {', '.join(map(str, open_ports))}")
            
            for port, service_info in services.items():
                service_name = service_info.get('name', 'unknown')
                product = service_info.get('product', '')
                version = service_info.get('version', '')
                
                service_desc = f"{service_name}"
                if product:
                    service_desc += f" ({product}"
                    if version:
                        service_desc += f" {version}"
                    service_desc += ")"
                
                logger.info(f"     {port}/tcp: {service_desc}")
    
    if active_hosts_no_ports:
        logger.info(f"\n🟡 ACTIVE HOSTS (no open ports detected):")
        logger.info("-" * 40)
        for subdomain, scan_data in active_hosts_no_ports[:10]:  # Show first 10
            ip_addr = scan_data.get('ip_address', 'N/A')
            logger.info(f"🟡 {subdomain} ({ip_addr}) - Host up, no open ports")
            if scan_data.get('scan_error'):
                logger.info(f"     Note: {scan_data['scan_error']}")
    
    if inactive_hosts and len(inactive_hosts) <= 10:
        logger.info(f"\n🔴 INACTIVE HOSTS:")
        for subdomain, scan_data in inactive_hosts:
            status = scan_data.get('is_active', 'unknown')
            logger.info(f"🔴 {subdomain} - Status: {status}")
    elif inactive_hosts:
        logger.info(f"\n🔴 INACTIVE HOSTS: {len(inactive_hosts)} hosts (showing first 5)")
        for subdomain, scan_data in inactive_hosts[:5]:
            status = scan_data.get('is_active', 'unknown')
            logger.info(f"🔴 {subdomain} - Status: {status}")
    
    if error_hosts:
        logger.info(f"\n❌ SCAN ERRORS:")
        for subdomain, scan_data in error_hosts[:5]:  # Show first 5 errors
            error = scan_data.get('error', 'Unknown error')
            logger.info(f"❌ {subdomain} - Error: {error}")

def save_new_subdomains(domain, subdomains_data):
    """
    Save subdomains with port scan data to database
    subdomains_data: list of tuples (subdomain, scan_data)
    """
    with engine.connect() as conn:
        for subdomain, scan_data in subdomains_data:
            try:
                # Convert lists/dicts to JSON strings for storage
                open_ports_json = ','.join(map(str, scan_data['open_ports'])) if scan_data['open_ports'] else ''
                services_json = str(scan_data['services']) if scan_data['services'] else ''
                
                stmt = insert(subdomains_table).values(
                    domain=domain, 
                    subdomain=subdomain, 
                    detected_at=datetime.utcnow(),
                    ip_address=scan_data.get('ip_address', ''),
                    is_active=scan_data.get('is_active', 'unknown'),
                    open_ports=open_ports_json,
                    services=services_json,
                    last_scanned=datetime.utcnow()
                )
                conn.execute(stmt)
                conn.commit()
                
            except Exception as e:
                if "Unknown column" in str(e):
                    # Fallback to basic insert
                    logger.warning(f"⚠️ Saving {subdomain} with basic schema only")
                    basic_stmt = insert(subdomains_table).values(
                        domain=domain, 
                        subdomain=subdomain, 
                        detected_at=datetime.utcnow()
                    )
                    conn.execute(basic_stmt)
                    conn.commit()
                else:
                    logger.error(f"❌ Error saving {subdomain}: {e}")

def update_subdomain_scan_data(domain, subdomains_data):
    """
    Update existing subdomains with new port scan data
    subdomains_data: list of tuples (subdomain, scan_data)
    """
    with engine.connect() as conn:
        for subdomain, scan_data in subdomains_data:
            try:
                # Convert lists/dicts to JSON strings for storage
                open_ports_json = ','.join(map(str, scan_data['open_ports'])) if scan_data['open_ports'] else ''
                services_json = str(scan_data['services']) if scan_data['services'] else ''
                
                # Update existing record
                stmt = subdomains_table.update().where(
                    (subdomains_table.c.domain == domain) & 
                    (subdomains_table.c.subdomain == subdomain)
                ).values(
                    ip_address=scan_data.get('ip_address', ''),
                    is_active=scan_data.get('is_active', 'unknown'),
                    open_ports=open_ports_json,
                    services=services_json,
                    last_scanned=datetime.utcnow()
                )
                conn.execute(stmt)
                conn.commit()
                
            except Exception as e:
                if "Unknown column" in str(e):
                    logger.warning(f"⚠️ Cannot update {subdomain} - new columns not available")
                else:
                    logger.error(f"❌ Error updating {subdomain}: {e}")

def detect_port_changes(existing_data, new_scan_results):
    """
    Detect changes in ports between existing data and new scan results
    Returns: (new_subdomains, port_changes)
    """
    new_subdomains = []
    port_changes = []
    
    for subdomain, new_scan_data in new_scan_results:
        if subdomain not in existing_data:
            # Completely new subdomain
            new_subdomains.append((subdomain, new_scan_data))
        else:
            # Existing subdomain - check for changes
            existing_scan = existing_data[subdomain]
            existing_ports = set(existing_scan.get('open_ports', []))
            new_ports = set(new_scan_data.get('open_ports', []))
            
            # Detect changes
            newly_opened = new_ports - existing_ports
            newly_closed = existing_ports - new_ports
            
            if newly_opened or newly_closed:
                change_info = {
                    'subdomain': subdomain,
                    'old_ip': existing_scan.get('ip_address', ''),
                    'new_ip': new_scan_data.get('ip_address', ''),
                    'old_ports': sorted(existing_ports),
                    'new_ports': sorted(new_ports),
                    'newly_opened': sorted(newly_opened),
                    'newly_closed': sorted(newly_closed),
                    'old_services': existing_scan.get('services', {}),
                    'new_services': new_scan_data.get('services', {})
                }
                port_changes.append(change_info)
    
    return new_subdomains, port_changes

def test_basic_functionality():
    """Test basic functionality before main execution"""
    logger.info("🧪 Running basic functionality tests...")
    
    # Test database connection
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            result.fetchone()
        logger.info("✅ Database connection successful")
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
        return False
    
    # Test DNS resolution
    try:
        resolver = dns.resolver.Resolver()
        resolver.resolve("google.com", "A")
        logger.info("✅ DNS resolution working")
    except Exception as e:
        logger.error(f"❌ DNS resolution failed: {e}")
        return False
    
    # Test HTTP requests
    try:
        resp = requests.get("https://httpbin.org/ip", timeout=10)
        logger.info(f"✅ HTTP requests working (IP: {resp.json().get('origin', 'unknown')})")
    except Exception as e:
        logger.error(f"❌ HTTP requests failed: {e}")
        return False
    
    return True

def main():
    logger.info("🚀 Starting Domain Monitor with Port Scanning")
    logger.info(f"Timestamp: {datetime.now(UTC)}")
    
    # Validate environment variables
    logger.info("📋 Checking environment variables...")
    if not DOMAINS_ENV:
        logger.error("❌ DOMAINS environment variable not set")
        sys.exit(1)
    logger.info(f"✅ DOMAINS found: {DOMAINS_ENV}")
    
    if not MYSQL_URL:
        logger.error("❌ DATABASE_URL environment variable not set")
        sys.exit(1)
    logger.info("✅ DATABASE_URL configured")
    
    if not EMAIL_USER or not EMAIL_PASS:
        logger.warning("⚠️ Email credentials not configured - notifications disabled")
    else:
        logger.info("✅ Email credentials configured")

    domains = [d.strip() for d in DOMAINS_ENV.strip("{} ").split(",") if d.strip()]
    if not domains:
        logger.error("❌ No valid domains provided")
        sys.exit(1)
    
    logger.info(f"📡 Will process {len(domains)} domains: {domains}")

    notifier = EmailNotifier(EMAIL_USER, EMAIL_PASS, EMAIL_TO)
    teams_notifier = TeamsNotifier(TEAMS_WEBHOOK_URL) if (TEAMS_AVAILABLE and TEAMS_WEBHOOK_URL) else None
    
    if teams_notifier:
        logger.info("✅ Teams notifications enabled")
    else:
        logger.info("⚠️ Teams notifications disabled (no webhook URL)")

    for i, domain in enumerate(domains, 1):
        logger.info(f"\n{'='*60}")
        logger.info(f"🎯 Processing domain {i}/{len(domains)}: {domain}")
        logger.info(f"{'='*60}")
        
        try:
            # Step 1: Discover subdomains
            logger.info("🔍 Step 1: Discovering subdomains...")
            all_subs = fetch_subdomains(domain)
            logger.info(f"📊 Found {len(all_subs)} total subdomains")
            
            # Step 2: Validate subdomains
            logger.info("🧪 Step 2: Validating DNS resolution...")
            active_subs = validate_subdomains(all_subs)
            logger.info(f"✅ {len(active_subs)} active subdomains for {domain}")

            # Step 3: Get existing subdomains and their scan data
            logger.info("💾 Step 3: Checking existing subdomains and scan data...")
            existing = get_existing_subdomains(domain)
            existing_scan_data = get_existing_scan_data(domain)
            new_subs = sorted(set(active_subs) - existing)
            logger.info(f"📈 Found {len(existing)} existing, {len(new_subs)} new subdomains")

            # Step 4: Perform port scanning on ALL active subdomains
            logger.info("🔬 Step 4: Starting comprehensive port scanning...")
            logger.info(f"⚡ Will scan {len(active_subs)} total subdomains (new + existing)")
            
            # Detect best nmap arguments once
            best_nmap_args = get_nmap_arguments()
            
            all_scan_results = []
            
            for j, subdomain in enumerate(active_subs, 1):
                logger.info(f"⚡ Scanning {j}/{len(active_subs)}: {subdomain}")
                scan_data = scan_subdomain_ports(subdomain, best_nmap_args)
                all_scan_results.append((subdomain, scan_data))
                
                # Show immediate results
                if scan_data.get('open_ports'):
                    logger.info(f"  🟢 Found {len(scan_data['open_ports'])} open ports: {scan_data['open_ports']}")
                else:
                    logger.info(f"  🔴 No open ports or host unreachable")

            # Step 5: Detect changes and new subdomains
            logger.info("🔍 Step 5: Analyzing changes in port status...")
            new_subdomains, port_changes = detect_port_changes(existing_scan_data, all_scan_results)
            
            logger.info(f"📊 Analysis results:")
            logger.info(f"   🆕 New subdomains: {len(new_subdomains)}")
            logger.info(f"   🔄 Port changes detected: {len(port_changes)}")

            # Step 6: Display comprehensive scan results
            logger.info("📊 Step 6: Displaying comprehensive scan results...")
            app.reporter.report.display_scan_results(all_scan_results)
            
            # Step 7: Save/update database with scan data
            logger.info("💾 Step 7: Updating database...")
            if new_subdomains:
                save_new_subdomains(domain, new_subdomains)
                logger.info(f"✅ Saved {len(new_subdomains)} new subdomains")
            
            # Update existing subdomains with new scan data
            existing_to_update = [(sub, data) for sub, data in all_scan_results if sub in existing]
            if existing_to_update:
                update_subdomain_scan_data(domain, existing_to_update)
                logger.info(f"✅ Updated {len(existing_to_update)} existing subdomains")
            
            # Step 8: Prepare and send notifications
            logger.info("📧 Step 8: Preparing notifications...")
            
            # Check if we have anything to notify about
            has_new_subdomains = len(new_subdomains) > 0
            has_port_changes = len(port_changes) > 0
            
            if has_new_subdomains or has_port_changes:
                logger.info("📨 Changes detected - preparing enhanced notification")
                
                # Build comprehensive notification message
                notification_message = f"Domain Monitoring Report for {domain}\n"
                notification_message += f"Scan completed at: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                notification_message += "="*60 + "\n\n"
                
                # New subdomains section
                if has_new_subdomains:
                    notification_message += f"🆕 NEW SUBDOMAINS DISCOVERED ({len(new_subdomains)}):\n"
                    notification_message += "-"*40 + "\n"
                    
                    for subdomain, scan_data in new_subdomains:
                        notification_message += f"🟢 {subdomain}\n"
                        notification_message += f"   IP: {scan_data.get('ip_address', 'N/A')}\n"
                        if scan_data.get('open_ports'):
                            notification_message += f"   Open ports: {', '.join(map(str, scan_data['open_ports']))}\n"
                            
                            # Add service information
                            services = scan_data.get('services', {})
                            if services:
                                notification_message += "   Services:\n"
                                for port, service_info in services.items():
                                    service_name = service_info.get('name', 'unknown')
                                    product = service_info.get('product', '')
                                    notification_message += f"     {port}/tcp: {service_name}"
                                    if product:
                                        notification_message += f" ({product})"
                                    notification_message += "\n"
                        else:
                            notification_message += "   No open ports detected\n"
                        notification_message += "\n"
                
                # Port changes section
                if has_port_changes:
                    notification_message += f"🔄 PORT CHANGES DETECTED ({len(port_changes)}):\n"
                    notification_message += "-"*40 + "\n"
                    
                    for change in port_changes:
                        subdomain = change['subdomain']
                        notification_message += f"🔀 {subdomain}\n"
                        
                        # IP changes
                        if change['old_ip'] != change['new_ip']:
                            notification_message += f"   IP changed: {change['old_ip']} → {change['new_ip']}\n"
                        else:
                            notification_message += f"   IP: {change['new_ip']}\n"
                        
                        # Port changes
                        if change['newly_opened']:
                            notification_message += f"   🟢 Newly opened ports: {', '.join(map(str, change['newly_opened']))}\n"
                            
                            # Show services for newly opened ports
                            new_services = change['new_services']
                            for port in change['newly_opened']:
                                port_str = str(port)
                                if port_str in new_services:
                                    service_info = new_services[port_str]
                                    service_name = service_info.get('name', 'unknown')
                                    product = service_info.get('product', '')
                                    notification_message += f"     {port}/tcp: {service_name}"
                                    if product:
                                        notification_message += f" ({product})"
                                    notification_message += "\n"
                        
                        if change['newly_closed']:
                            notification_message += f"   🔴 Newly closed ports: {', '.join(map(str, change['newly_closed']))}\n"
                        
                        notification_message += f"   Previous ports: {', '.join(map(str, change['old_ports'])) if change['old_ports'] else 'None'}\n"
                        notification_message += f"   Current ports: {', '.join(map(str, change['new_ports'])) if change['new_ports'] else 'None'}\n"
                        notification_message += "\n"
                
                # Summary section
                notification_message += "� SUMMARY:\n"
                notification_message += "-"*20 + "\n"
                notification_message += f"Total subdomains scanned: {len(active_subs)}\n"
                notification_message += f"New subdomains: {len(new_subdomains)}\n"
                notification_message += f"Subdomains with port changes: {len(port_changes)}\n"
                
                # Count total hosts with open ports
                hosts_with_ports = sum(1 for _, data in all_scan_results if data.get('open_ports'))
                notification_message += f"Hosts with open ports: {hosts_with_ports}\n"
                
                # Send enhanced notification
                logger.info("📤 Sending comprehensive notification with changes")
                notifier.send_enhanced(domain, notification_message)
                
                # Send Teams notification if configured
                if teams_notifier:
                    logger.info("📤 Sending Teams notifications...")
                    
                    # Send summary report to Teams
                    teams_domains_data = []
                    for subdomain, scan_data in all_scan_results:
                        if scan_data.get('open_ports'):
                            teams_domains_data.append({
                                'domain': subdomain,
                                'days_left': 365  # Port scanning doesn't have expiration data
                            })
                    
                    if teams_domains_data:
                        teams_notifier.send_summary_report(teams_domains_data[:10])  # Send top 10
                    
                    # Send tabla resumen de cambios de puertos
                    if port_changes:
                        table_rows = []
                        for change in port_changes:
                            subdomain = change['subdomain']
                            old_ports = ', '.join(map(str, change['old_ports'])) if change['old_ports'] else '-'
                            new_ports = ', '.join(map(str, change['new_ports'])) if change['new_ports'] else '-'
                            newly_opened = ', '.join(map(str, change['newly_opened'])) if change['newly_opened'] else '-'
                            newly_closed = ', '.join(map(str, change['newly_closed'])) if change['newly_closed'] else '-'
                            table_rows.append(f"| `{subdomain}` | `{old_ports}` | `{new_ports}` | `{newly_opened}` | `{newly_closed}` |")

                        table_header = (
                            "| Subdomain | Old Ports | New Ports | Newly Opened | Newly Closed |\n"
                            "|-----------|-----------|-----------|--------------|--------------|"
                        )
                        table = table_header + "\n" + "\n".join(table_rows)

                        teams_message = {
                            "@type": "MessageCard",
                            "@context": "http://schema.org/extensions",
                            "themeColor": "FFA500",
                            "summary": f"Port Changes Detected for {domain}",
                            "title": f"🔄 Port Changes Detected for {domain}",
                            "sections": [{
                                "activityTitle": f"🔄 Port Changes Summary ({len(port_changes)} changes)",
                                "markdown": True,
                                "text": (
                                    f"Se detectaron cambios en los puertos de los siguientes subdominios:\n\n"
                                    f"{table}\n\n"
                                    f"_Revisa los cambios y toma acción si es necesario._"
                                )
                            }]
                        }

                        try:
                            import requests
                            response = requests.post(
                                TEAMS_WEBHOOK_URL,
                                headers={'Content-Type': 'application/json'},
                                json=teams_message,
                                timeout=10
                            )
                            response.raise_for_status()
                            logger.info("✅ Teams summary table sent successfully")
                        except Exception as e:
                            logger.error(f"❌ Error sending Teams summary table: {e}")
                
                logger.info(f"✅ Completed processing for {domain}")
            else:
                logger.info(f"ℹ️ No new subdomains or port changes for {domain} - no notification sent")
                
        except Exception as e:
            logger.error(f"❌ Error processing domain {domain}: {e}")
            logger.error(f"Error details: {str(e)}")
            continue
    
    logger.info("\n🎉 Domain monitoring completed successfully!")
    logger.info(f"Final timestamp: {datetime.now(UTC)}")

if __name__ == "__main__":
    try:
        logger.info("🚀 Domain Monitor starting...")
        logger.info(f"Python version: {sys.version}")
        logger.info(f"Working directory: {os.getcwd()}")
        
        # Ensure database schema is up to date
        ensure_database_schema()
        
        # Run basic tests first
        if not test_basic_functionality():
            logger.error("❌ Basic functionality tests failed, exiting")
            sys.exit(1)
        
        # Test nmap availability and capabilities
        try:
            nm = nmap.PortScanner()
            logger.info("✅ Nmap library loaded successfully")
            
            # Test basic nmap functionality
            try:
                test_result = nm.scan('127.0.0.1', '80')
                logger.info("✅ Basic nmap scan test successful")
            except Exception as nmap_test_error:
                logger.warning(f"⚠️ Nmap basic test failed: {nmap_test_error}")
                
        except Exception as e:
            logger.error(f"❌ Nmap not available: {e}")
            logger.warning("⚠️ Continuing without port scanning capabilities")
            
        main()
    except KeyboardInterrupt:
        logger.info("⚠️ Program interrupted by user")
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        logger.error(f"Error type: {type(e).__name__}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        sys.exit(1)
