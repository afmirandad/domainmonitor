import requests
from app.config.settings import TEAMS_WEBHOOK_URL, logger

class TeamsNotifier:
    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url or TEAMS_WEBHOOK_URL

    def send_summary_report(self, domains_data):
        if not self.webhook_url:
            logger.warning("Teams webhook URL not configured.")
            return
        table_header = (
            "| Domain | Days Left |\n"
            "|--------|-----------|"
        )
        table_rows = [f"| `{d['domain']}` | `{d['days_left']}` |" for d in domains_data]
        table = table_header + "\n" + "\n".join(table_rows)
        message = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0076D7",
            "summary": "Domain Monitoring Report",
            "title": "Domain Monitoring Report",
            "sections": [{
                "activityTitle": "Domain Monitoring Summary",
                "markdown": True,
                "text": table
            }]
        }
        try:
            response = requests.post(
                self.webhook_url,
                headers={'Content-Type': 'application/json'},
                json=message,
                timeout=10
            )
            response.raise_for_status()
            logger.info("Teams summary report sent successfully.")
        except Exception as e:
            logger.error(f"Error sending Teams summary report: {e}")

    def send_port_changes(self, domain, port_changes):
        if not self.webhook_url:
            logger.warning("Teams webhook URL not configured.")
            return
        table_header = (
            "| Subdomain | Port | New Status |\n"
            "|-----------|------|------------|"
        )
        table_rows = []
        for change in port_changes:
            subdomain = change['subdomain']
            # For each port that changed, show its new status
            for port in change.get('newly_opened', []):
                table_rows.append(f"| `{subdomain}` | `{port}` | `open` |")
            for port in change.get('newly_closed', []):
                table_rows.append(f"| `{subdomain}` | `{port}` | `closed` |")
        if not table_rows:
            table_rows.append("| - | - | - |")
        table = table_header + "\n" + "\n".join(table_rows)
        message = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FFA500",
            "summary": f"Port Changes Detected for {domain}",
            "title": f"🔄 Port Changes Detected for {domain}",
            "sections": [{
                "activityTitle": f"🔄 Port Changes Summary ({len(port_changes)} changes)",
                "markdown": True,
                "text": table
            }]
        }
        try:
            response = requests.post(
                self.webhook_url,
                headers={'Content-Type': 'application/json'},
                json=message,
                timeout=10
            )
            response.raise_for_status()
            logger.info("Teams port changes table sent successfully.")
        except Exception as e:
            logger.error(f"Error sending Teams port changes table: {e}")
