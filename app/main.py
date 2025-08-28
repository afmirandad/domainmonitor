from app.config.settings import logger, MYSQL_URL, EMAIL_USER, EMAIL_PASS, EMAIL_TO, DOMAINS_ENV, TEAMS_WEBHOOK_URL
from app.runners.hackertarget import fetch_hackertarget_subdomains
from app.runners.rapiddns import fetch_rapiddns_subdomains
from app.runners.certspotter import fetch_certspotter_subdomains
from app.runners.crtsh import fetch_crtsh_subdomains
from app.runners.validate_subdomains import validate_subdomains
from app.runners.scan_subdomain_ports import scan_subdomain_ports

def log_section(title):
    logger.info("\n" + "="*60)
    logger.info(title)
    logger.info("="*60)

def main():
    test_domain = "invotecsa.com"
    log_section(f"Testing all runners with domain: {test_domain}")

    # HackerTarget
    hackertarget_subs = fetch_hackertarget_subdomains(test_domain)
    log_section("HackerTarget Subdomains")
    logger.info(hackertarget_subs)

    # RapidDNS
    rapiddns_subs = fetch_rapiddns_subdomains(test_domain)
    log_section("RapidDNS Subdomains")
    logger.info(rapiddns_subs)

    # CertSpotter
    certspotter_subs = fetch_certspotter_subdomains(test_domain)
    log_section("CertSpotter Subdomains")
    logger.info(certspotter_subs)

    # crt.sh
    crtsh_subs = fetch_crtsh_subdomains(test_domain)
    log_section("crt.sh Subdomains")
    logger.info(crtsh_subs)

    # Validate subdomains (using all found)
    all_subs = set(hackertarget_subs + rapiddns_subs + certspotter_subs + crtsh_subs)
    valid_subs = validate_subdomains(list(all_subs))
    log_section("Validated Subdomains (DNS Resolved)")
    logger.info(valid_subs)

    # Scan ports for up to 3 valid subdomains
    log_section("Port Scan Results (first 3 valid subdomains)")
    for sub in valid_subs[:3]:
        scan_result = scan_subdomain_ports(sub)
        logger.info(f"Subdomain: {sub}")
        logger.info(scan_result)
        logger.info("-"*40)

if __name__ == "__main__":
    logger.info("App started!")
    logger.info(f"MYSQL_URL: {MYSQL_URL}")
    logger.info(f"EMAIL_USER: {EMAIL_USER}")
    logger.info(f"EMAIL_TO: {EMAIL_TO}")
    logger.info(f"DOMAINS_ENV: {DOMAINS_ENV}")
    #logger.info(f"TEAMS_WEBHOOK_URL: {TEAMS_WEBHOOK_URL}")
    main()
