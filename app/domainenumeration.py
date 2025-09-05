"""
Domain Enumeration Entrypoint
"""
from app.services.subdomain_enumeration_service import SubdomainEnumerationService
from app.services.teams_report_service import TeamsReportService
from app.config.settings import logger

def main():
    logger.info("Starting domain enumeration...")
    SubdomainEnumerationService.enumerate_and_store()
    logger.info("Domain enumeration completed.")
    TeamsReportService.send_new_subdomains_report()
    logger.info("New subdomains report sent.")

if __name__ == "__main__":
    main()
