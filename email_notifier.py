import logging
import yagmail

logger = logging.getLogger(__name__)

class EmailNotifier:
    def __init__(self, user, password, recipients):
        self.user = user
        self.password = password
        self.recipients = recipients.split(',') if recipients else []

        if not self.user or not self.password:
            logger.error("Email user or password not provided.")
            self.yag = None
            return

        try:
            self.yag = yagmail.SMTP(self.user, self.password)
            logger.info("Email client initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize email client: {e}")
            self.yag = None

    def send(self, domain, subdomains):
        if not self.yag or not self.recipients:
            logger.warning("Email not sent: missing yagmail client or recipients.")
            return

        subject = f"[Subdomain Report] New entries for {domain}"
        body = f"Detected new active subdomains for {domain}:\n\n" + "\n".join(subdomains)

        try:
            self.yag.send(to=self.recipients, subject=subject, contents=body)
            logger.info(f"Email sent for domain {domain} to: {', '.join(self.recipients)}")
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
