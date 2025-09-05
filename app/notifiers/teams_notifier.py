import requests
from app.config.settings import TEAMS_WEBHOOK_URL, logger

class TeamsNotifier:

    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url or TEAMS_WEBHOOK_URL

    def send_new_subdomains_notification(self, new_subdomains):
        if not self.webhook_url:
            logger.warning("Teams webhook URL not configured.")
            return
        if not new_subdomains:
            logger.info("No new subdomains to notify.")
            return
        subdomains_text = '\n'.join(f"- {sub}" for sub in new_subdomains)
        message = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0076D7",
            "summary": "New Subdomains Detected",
            "title": "New Subdomains Detected",
            "sections": [{
                "activityTitle": "New subdomains have been discovered:",
                "activityImage": "https://cdn-icons-png.flaticon.com/512/2039/2039001.png",
                "markdown": True,
                "text": subdomains_text
            }]
        }
        try:
            response = requests.post(
                self.webhook_url,
                headers={'Content-Type': 'application/json'},
                json=message,
                timeout=10
            )
            logger.info(f"Teams response status: {response.status_code}, body: {response.text}")
        except Exception as e:
            logger.error(f"Error sending Teams new subdomains notification: {e}")

    def send_custom_report(self, title, text):
        if not self.webhook_url:
            logger.warning("Teams webhook URL not configured.")
            return
        message = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0076D7",
            "summary": title,
            "title": title,
            "sections": [{
                "activityTitle": "New ports were detected",
                "activityImage": "https://cdn-icons-png.flaticon.com/512/2039/2039001.png",
                "facts": [
                    {"name": "Assigned to", "value": "Unassigned"},
                    {"name": "Due date", "value": "Mon May 01 2017 17:07:18 GMT-0700 (Pacific Daylight Time)"},
                    {"name": "Status", "value": "Not started"}
                ],
                "markdown": True,
                "text": text
            }]
        }
        try:
            response = requests.post(
                self.webhook_url,
                headers={'Content-Type': 'application/json'},
                json=message,
                timeout=10
            )
            logger.info(f"Teams response status: {response.status_code}, body: {response.text}")
        except Exception as e:
            logger.error(f"Error sending Teams custom report: {e}")
