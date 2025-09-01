from app.notifiers.teams_notifier import TeamsNotifier
from app.reporter.report import get_ports_report_text
from app.config.settings import logger, TEAMS_WEBHOOK_URL
import requests

class TeamsReportService:
    @staticmethod
    def send_ports_report():
        teams = TeamsNotifier()
        logger.info("Generating ports report for Teams...")
        report_text = get_ports_report_text()
        logger.info(f"Report text generated:\n{report_text}")
        # Enviar tabla como mensaje a Teams
        try:
            message = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "0076D7",
                "summary": "Ports Report",
                "title": "Subdomains & Ports Report",
                "sections": [{
                    "activityTitle": "Subdomains & Ports Table",
                    "markdown": True,
                    "text": report_text
                }]
            }
            if TEAMS_WEBHOOK_URL:
                logger.info(f"Sending report to Teams webhook: {TEAMS_WEBHOOK_URL}")
                resp = requests.post(TEAMS_WEBHOOK_URL, headers={'Content-Type': 'application/json'}, json=message, timeout=10)
                logger.info(f"Teams response status: {resp.status_code}, body: {resp.text}")
            else:
                logger.warning("TEAMS_WEBHOOK_URL is not set. Skipping Teams notification.")
        except Exception as e:
            logger.error(f"Error sending Teams ports report: {e}")
