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
├── app/
│   ├── domainenumeration.py         # Main application entry point
│   ├── config/
│   │   ├── database.py              # SQLAlchemy engine and schema logic
│   │   └── settings.py              # Environment/config loader
│   ├── models/
│   │   ├── subdomains.py            # Subdomain table/model
│   │   ├── ports.py                 # Ports table/model
│   │   └── vulnerabilities.py       # Vulnerabilities table/model
│   ├── notifiers/
│   │   ├── email_notifier.py        # Email notification handler
│   │   └── teams_notifier.py        # Teams notification handler
│   ├── reporter/
│   │   ├── report.py                # Reporting logic
│   │   ├── subdomain_change_detector.py # Change detection for subdomains
│   │   └── ports_change_detector.py # Change detection for ports
│   ├── runners/
│   │   ├── certspotter.py           # CertSpotter API integration
│   │   ├── crtsh.py                 # crt.sh integration
│   │   ├── hackertarget.py          # HackerTarget API integration
│   │   ├── rapiddns.py              # RapidDNS API integration
│   │   ├── scan_subdomain_ports.py  # Port and vulnerability scanning
│   │   └── validate_subdomains.py   # DNS validation
│   └── services/
│       ├── port_enumeration_service.py   # Port scan orchestration
│       ├── subdomain_enumeration_service.py # Subdomain discovery orchestration
│       └── teams_report_service.py       # Teams reporting orchestration
├── requirements.txt
├── Dockerfile
├── .env
├── .gitignore
└── README.md
```

## 🔧 Technical Architecture

- **Main Application** (`app/domainenumeration.py`): Orchestrates monitoring, scanning, and notifications.
- **Notifiers** (`app/notifiers/`): Email and Teams notifications.
- **Database Layer** (`app/config/database.py`): SQLAlchemy + PyMySQL.
- **Services & Runners**: Modular orchestration and API integrations.
- **Reporter**: Change detection and reporting.
- **Docker**: Containerized deployment.

## Subdomain Discovery Sources

- HackerTarget API
- RapidDNS
- CertSpotter API
- crt.sh

## Environment Configuration

```bash
# Database Configuration (PyMySQL driver required)
DATABASE_URL=mysql+pymysql://username:password@host:port/database_name

# Email Configuration
EMAIL_USER=your-email@domain.com
EMAIL_PASSWORD=your-app-password
EMAIL_TO=recipient1@domain.com,recipient2@domain.com

# Teams Webhook (optional)
TEAMS_WEBHOOK_URL=https://your-teams-webhook-url

# Target Domains (comma-separated)
DOMAINS=example.com,target.org,company.net
```

## Docker Deployment

```bash
docker build -t domainmonitor .
docker run --env-file .env domainmonitor
# O bien, pasando variables directamente:
docker run --rm -e DOMAINS=example.com -e DATABASE_URL='mysql+pymysql://username:password@host:port/database_name' domainmonitor
```

## Docker Compose

```yaml
version: '3.8'

services:
  domainmonitor:
    build: .
    env_file: .env
    restart: unless-stopped
    depends_on:
      - mysql

  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
      MYSQL_DATABASE: railway
      MYSQL_USER: ${MYSQL_USER}
      MYSQL_PASSWORD: ${MYSQL_PASSWORD}
    volumes:
      - mysql_data:/var/lib/mysql
    ports:
      - "3306:3306"

volumes:
  mysql_data:
```

## Cron Example

```bash
0 * * * * docker run --rm --env-file /path/to/.env domainmonitor
```
