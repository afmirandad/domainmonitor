from app.notifiers.teams_notifier import TeamsNotifier
from app.reporter.report import get_ports_report_text
from app.config.settings import logger
from app.services.port_enumeration_service import PortEnumerationService

class TeamsReportService:
    @staticmethod
    def send_new_subdomains_report(new_subdomains=None, since_minutes=10):
        """Send a Teams notification for new subdomains. If no list is provided, detect new subdomains from DB."""
        if new_subdomains is None:
            from app.reporter.subdomain_change_detector import get_new_subdomains
            new_subdomains = get_new_subdomains(since_minutes)
        if not new_subdomains:
            logger.info("No new subdomains to report.")
            return
        teams = TeamsNotifier()
        logger.info(f"Sending new subdomains notification: {new_subdomains}")
        teams.send_new_subdomains_notification(new_subdomains)
        PortEnumerationService.enumerate_and_store_ports_for_subdomains_ondemand(new_subdomains)


    @staticmethod
    def send_ports_report():
        from app.reporter.ports_change_detector import has_new_or_changed_ports
        if not has_new_or_changed_ports():
            logger.info("No new or changed ports detected. Report will not be sent.")
            return
        teams = TeamsNotifier()
        logger.info("Generating ports report for Teams...")
        report_text = get_ports_report_text()
        logger.info(f"Report text generated:\n{report_text}")
        teams.send_custom_report(
            title="Subdomains & Ports Report",
            text=report_text
        )
    
