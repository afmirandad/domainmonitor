import smtplib
from email.mime.text import MIMEText
from app.config.settings import EMAIL_USER, EMAIL_PASSWORD, EMAIL_TO, logger

class EmailNotifier:
    def __init__(self, user=None, password=None, to=None):
        self.user = user or EMAIL_USER
        self.password = password or EMAIL_PASSWORD
        self.to = to or EMAIL_TO

    def send_enhanced(self, domain, message):
        if not (self.user and self.password and self.to):
            logger.warning("Email credentials or recipient not configured.")
            return
        msg = MIMEText(message)
        msg['Subject'] = f"Domain Monitoring Report for {domain}"
        msg['From'] = self.user
        msg['To'] = self.to
        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(self.user, self.password)
                server.sendmail(self.user, [self.to], msg.as_string())
            logger.info("Email notification sent successfully.")
        except Exception as e:
            logger.error(f"Error sending email notification: {e}")
