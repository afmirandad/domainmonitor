# Domain Monitor

A comprehensive subdomain monitoring and alerting system that continuously tracks and reports new subdomains for specified domains using multiple reconnaissance sources.

## 🚀 Features

- **Multi-source subdomain discovery** using 5 different reconnaissance techniques
- **Real-time validation** of discovered subdomains via DNS resolution
- **Persistent storage** with MySQL database integration
- **Email notifications** for newly discovered active subdomains
- **Dockerized deployment** for easy scalability and consistency
- **Comprehensive logging** for monitoring and debugging
- **Automated deduplication** to avoid redundant notifications

## 📁 Project Structure

```
domainmonitor/
├── 📄 entrypoint.py          # Main application entry point
├── 📄 email_notifier.py      # Email notification handler
├── 📄 requirements.txt       # Python dependencies
├── 📄 Dockerfile            # Container configuration
├── 📄 subs_clean.txt        # Subdomain wordlist/reference
├── 📄 .env                  # Environment variables (not tracked)
├── 📄 .gitignore           # Git ignore rules
└── 📄 README.md            # Project documentation
```

## 🔧 Technical Architecture

### Core Components

#### 1. **Main Application** (`entrypoint.py`)
The primary orchestrator that coordinates all monitoring activities.

#### 2. **Email Notifier** (`email_notifier.py`)
Handles SMTP-based email notifications for new subdomain discoveries.

#### 3. **Database Layer**
SQLAlchemy-based MySQL integration for persistent subdomain tracking.

#### 4. **Container Environment**
Docker-based deployment with Go tools for advanced subdomain enumeration.

## 🔍 Functional Scope

### Subdomain Discovery Sources

The application leverages multiple reconnaissance techniques:

1. **Subfinder** - ProjectDiscovery's passive subdomain discovery tool
2. **HackerTarget API** - DNS reconnaissance service
3. **RapidDNS** - DNS database queries
4. **CertSpotter API** - Certificate transparency logs
5. **crt.sh** - Certificate transparency search

### Core Workflows

1. **Discovery Phase**: Enumerate subdomains from all sources
2. **Validation Phase**: DNS resolution testing for active subdomains
3. **Persistence Phase**: Store results in MySQL database
4. **Notification Phase**: Email alerts for new discoveries
5. **Deduplication**: Compare against historical data to avoid duplicates

## 📋 Step-by-Step Application Behavior

### Startup Sequence

1. **Environment Validation**
   ```python
   # Load and validate required environment variables
   DATABASE_URL = os.getenv("DATABASE_URL")
   EMAIL_USER = os.getenv("EMAIL_USER")
   EMAIL_PASS = os.getenv("EMAIL_PASSWORD")
   EMAIL_TO = os.getenv("EMAIL_TO")
   DOMAINS_ENV = os.getenv("DOMAINS")
   ```

2. **Database Initialization**
   ```python
   # Create SQLAlchemy engine and table schema
   engine = create_engine(MYSQL_URL)
   subdomains_table = Table('subdomains', metadata, ...)
   metadata.create_all(engine)
   ```

3. **Domain Processing Loop**
   - Parse comma-separated domain list from environment
   - Initialize email notifier with SMTP credentials

### Per-Domain Execution Flow

#### Phase 1: Subdomain Discovery (`fetch_subdomains()`)

**Subfinder Integration**
```bash
subfinder -d example.com -silent
```
- Executes external Go binary via subprocess
- Captures stdout for subdomain list
- Graceful error handling with logging

**API-based Discovery**
- **HackerTarget**: `GET https://api.hackertarget.com/hostsearch/?q={domain}`
- **RapidDNS**: `GET https://rapiddns.io/subdomain/{domain}?plain=1`
- **CertSpotter**: `GET https://api.certspotter.com/v1/issuances?domain={domain}`
- **crt.sh**: `GET https://crt.sh/?q=%25.{domain}&output=json`

**Data Processing**
- Convert all results to lowercase for consistency
- Remove duplicates using Python sets
- Filter results to ensure they belong to target domain

#### Phase 2: DNS Validation (`validate_subdomains()`)

```python
resolver = dns.resolver.Resolver()
for subdomain in discovered_subdomains:
    try:
        resolver.resolve(subdomain, "A")
        active_subdomains.append(subdomain)
    except:
        # Subdomain doesn't resolve, skip
        pass
```

- Performs DNS A record lookups for each discovered subdomain
- Only retains subdomains that successfully resolve
- Uses dnspython library for reliable DNS operations

#### Phase 3: Persistence and Deduplication

**Historical Data Retrieval**
```python
def get_existing_subdomains(domain):
    with engine.connect() as conn:
        result = conn.execute(
            select(subdomains_table.c.subdomain)
            .where(subdomains_table.c.domain == domain)
        )
        return set(row[0] for row in result.fetchall())
```

**New Subdomain Detection**
```python
existing_subdomains = get_existing_subdomains(domain)
new_subdomains = sorted(set(active_subdomains) - existing_subdomains)
```

**Database Storage**
```python
def save_new_subdomains(domain, subdomains):
    with engine.connect() as conn:
        for subdomain in subdomains:
            stmt = insert(subdomains_table).values(
                domain=domain,
                subdomain=subdomain,
                detected_at=datetime.utcnow()
            )
            conn.execute(stmt)
        conn.commit()
```

#### Phase 4: Notification System

**Email Alert Generation**
```python
if new_subdomains:
    notifier.send(domain, new_subdomains)
```

**SMTP Configuration** (`email_notifier.py`)
- Uses yagmail for simplified SMTP operations
- Supports multiple recipients via comma-separated emails
- Generates structured email reports with subdomain lists

## 🚢 Deployment Guide

### Prerequisites

- Docker Engine 20.10+
- MySQL 8.0+ database instance
- SMTP-enabled email account
- Target domains for monitoring

### Environment Configuration

Create a `.env` file with the following variables:

```bash
# Database Configuration
DATABASE_URL=mysql://username:password@host:port/database_name

# Email Configuration
EMAIL_USER=your-email@domain.com
EMAIL_PASSWORD=your-app-password
EMAIL_TO=recipient1@domain.com,recipient2@domain.com

# Target Domains (comma-separated)
DOMAINS=example.com,target.org,company.net
```

### Database Setup

**MySQL Schema Creation**
```sql
CREATE DATABASE domain_monitor;
USE domain_monitor;

-- Table will be auto-created by SQLAlchemy
-- Structure: id, domain, subdomain, detected_at
```

### Docker Deployment

#### Option 1: Build and Run Locally

```bash
# Clone the repository
git clone <repository-url>
cd domainmonitor

# Build the Docker image
docker build -t domain-monitor .

# Run the container
docker run --env-file .env domain-monitor
```

#### Option 2: Docker Compose (Recommended)

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  domain-monitor:
    build: .
    env_file: .env
    restart: unless-stopped
    depends_on:
      - mysql

  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
      MYSQL_DATABASE: domain_monitor
      MYSQL_USER: ${MYSQL_USER}
      MYSQL_PASSWORD: ${MYSQL_PASSWORD}
    volumes:
      - mysql_data:/var/lib/mysql
    ports:
      - "3306:3306"

volumes:
  mysql_data:
```

**Deployment Commands**
```bash
# Start the complete stack
docker-compose up -d

# View logs
docker-compose logs -f domain-monitor

# Stop the stack
docker-compose down
```

### Scheduled Execution

#### Using Cron (Linux/macOS)

```bash
# Edit crontab
crontab -e

# Add entry for hourly execution
0 * * * * docker run --rm --env-file /path/to/.env domain-monitor
```

#### Using Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: domain-monitor
spec:
  schedule: "0 */6 * * *"  # Every 6 hours
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: domain-monitor
            image: domain-monitor:latest
            envFrom:
            - secretRef:
                name: domain-monitor-secrets
          restartPolicy: OnFailure
```

## 🔒 Security Considerations

- **Environment Variables**: Never commit `.env` files to version control
- **Database Credentials**: Use strong passwords and limit database access
- **Email Security**: Use app-specific passwords for Gmail/OAuth where possible
- **Network Security**: Consider running in isolated Docker networks
- **API Rate Limits**: Built-in error handling for API service limitations

## 📊 Monitoring and Logs

### Log Levels and Output

```
%(asctime)s [%(levelname)s] %(message)s
```

**Key Log Messages:**
- `INFO`: Successful operations, subdomain counts, email notifications
- `WARNING`: API failures, service timeouts
- `ERROR`: Database connections, environment variable issues

### Operational Metrics

- Subdomains discovered per domain
- Active vs inactive subdomain ratios
- API service success rates
- Email delivery confirmations

## 🛠 Development and Customization

### Adding New Discovery Sources

1. **Implement discovery function**:
```python
def custom_source_discovery(domain):
    # Your discovery logic here
    return list_of_subdomains
```

2. **Integrate in `fetch_subdomains()`**:
```python
try:
    custom_results = custom_source_discovery(domain)
    subdomains.update(custom_results)
except Exception as e:
    logger.warning(f"Custom source failed: {e}")
```

### Database Schema Extensions

Modify the table definition in `entrypoint.py`:
```python
subdomains_table = Table(
    'subdomains', metadata,
    Column('id', Integer, primary_key=True),
    Column('domain', String(255)),
    Column('subdomain', String(255)),
    Column('detected_at', DateTime, default=datetime.now(UTC)),
    Column('source', String(100)),  # New column
    Column('ip_address', String(45))  # New column
)
```

## 📈 Future Enhancements

- **Web Dashboard**: Real-time monitoring interface
- **Webhook Integration**: Slack, Discord, Teams notifications
- **Advanced Filtering**: IP range validation, subdomain pattern matching
- **Historical Analytics**: Trend analysis and reporting
- **Multi-threading**: Parallel domain processing
- **API Endpoint**: RESTful API for external integrations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with appropriate logging
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
