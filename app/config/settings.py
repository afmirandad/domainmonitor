import os
import logging
import urllib3
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Disable SSL warnings for the HTTP fallback checks
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Logger setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Environment variables
MYSQL_URL = os.getenv("DATABASE_URL")
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASSWORD")
EMAIL_TO = os.getenv("EMAIL_TO")
DOMAINS_ENV = os.getenv("DOMAINS")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL")

__all__ = [
    "MYSQL_URL",
    "EMAIL_USER",
    "EMAIL_PASS",
    "EMAIL_TO",
    "DOMAINS_ENV",
    "TEAMS_WEBHOOK_URL",
    "logger"
]
