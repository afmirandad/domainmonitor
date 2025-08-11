import logging
import yagmail
from datetime import datetime

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

    def send_enhanced(self, domain, enhanced_message):
        """Send enhanced email with port scan results and changes"""
        if not self.yag or not self.recipients:
            logger.warning("Enhanced email not sent: missing yagmail client or recipients.")
            return

        # Determine subject based on content
        if "PORT CHANGES DETECTED" in enhanced_message:
            if "NEW SUBDOMAINS DISCOVERED" in enhanced_message:
                subject = f"[Domain Monitor] New subdomains + Port changes detected for {domain}"
            else:
                subject = f"[Port Alert] Port changes detected for {domain}"
        elif "NEW SUBDOMAINS DISCOVERED" in enhanced_message:
            subject = f"[Security Alert] New subdomains discovered for {domain}"
        else:
            subject = f"[Domain Monitor] Scan report for {domain}"

        try:
            self.yag.send(to=self.recipients, subject=subject, contents=enhanced_message)
            logger.info(f"Enhanced email sent for domain {domain} to: {', '.join(self.recipients)}")
        except Exception as e:
            logger.error(f"Failed to send enhanced email: {e}")

    def send_port_changes_only(self, domain, port_changes):
        """Send notification for port changes only (no new subdomains)"""
        if not self.yag or not self.recipients:
            logger.warning("Port changes email not sent: missing yagmail client or recipients.")
            return

        subject = f"[Port Alert] Port status changes detected for {domain}"
        
        body = f"Port Changes Detected for {domain}\n"
        body += f"Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        body += "="*50 + "\n\n"
        
        for change in port_changes:
            subdomain = change['subdomain']
            body += f"🔀 {subdomain}\n"
            
            if change['newly_opened']:
                body += f"   🟢 Newly opened: {', '.join(map(str, change['newly_opened']))}\n"
            
            if change['newly_closed']:
                body += f"   🔴 Newly closed: {', '.join(map(str, change['newly_closed']))}\n"
            
            body += f"   Previous: {', '.join(map(str, change['old_ports'])) if change['old_ports'] else 'None'}\n"
            body += f"   Current: {', '.join(map(str, change['new_ports'])) if change['new_ports'] else 'None'}\n\n"

        try:
            self.yag.send(to=self.recipients, subject=subject, contents=body)
            logger.info(f"Port changes email sent for domain {domain} to: {', '.join(self.recipients)}")
        except Exception as e:
            logger.error(f"Failed to send port changes email: {e}")
