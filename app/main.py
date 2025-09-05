

from app.config.settings import logger
from app.services.subdomain_enumeration_service import SubdomainEnumerationService
from app.services.port_enumeration_service import PortEnumerationService
from app.services.teams_report_service import TeamsReportService

def log_section(title):
    logger.info("\n" + "="*60)
    logger.info(title)
    logger.info("="*60)

def main():
    SubdomainEnumerationService.enumerate_and_store()
    PortEnumerationService.enumerate_and_store_ports()
    TeamsReportService.send_ports_report()

if __name__ == "__main__":
    main()
