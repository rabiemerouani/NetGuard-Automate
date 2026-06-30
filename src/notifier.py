import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("NetGuard." + __name__)

def send_security_alert(device_name, vulnerabilities):
    """Generates and sends an email alert based on discovered CIS vulnerabilities."""
    
    sender_email = os.getenv("SMTP_SENDER")
    password = os.getenv("SMTP_PASSWORD")
    receiver_email = os.getenv("SMTP_RECEIVER")

    if not sender_email or not password or not receiver_email:
        logger.error("[SMTP] Incomplete SMTP configuration inside the .env file.")
        return

    # Only send an email if actual vulnerabilities are found
    if not vulnerabilities:
        logger.info(f"[SMTP] No compliance gaps found for {device_name}. Skipping email notification.")
        return

    logger.info(f"[SMTP] Preparing security alert dispatch for {device_name}...")
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = f"SECURITY ALERT: CIS Non-Compliance Detected on {device_name}"

    # Build the English compliance report body
    body = f"Hello,\n\n"
    body += f"An automated security configuration audit based on CIS Benchmarks was performed on: {device_name}\n"
    body += f"Status: WARNING - {len(vulnerabilities)} compliance gap(s) identified.\n"
    body += "======================================================================\n\n"

    for vuln in vulnerabilities:
        body += f"[{vuln['severity']}] {vuln['issue']}\n"
        body += f"    Category: {vuln['category']}\n"
        body += f"    CIS Level: Level {vuln['level']}\n"
        body += f"    Details  : {vuln['details']}\n"
        body += f"    Remediation: {vuln['fix']}\n"
        body += "----------------------------------------------------------------------\n"

    body += f"\nPlease remediate these vulnerabilities immediately to harden network infrastructure parameters.\n\n"
    body += f"Regards,\n"
    body += f"NetGuard Automation Suite."

    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    try:
        logger.debug("Connecting to smtp.gmail.com on port 587...")
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        
        logger.debug("Authenticating with Google mail server gateway...")
        server.login(sender_email, password)
        
        logger.info(f" Dispatching alert payload to {receiver_email}...")
        server.sendmail(sender_email, receiver_email, msg.as_string())
        
        logger.info(" Security alert email successfully dispatched!")
        server.quit()
        
    except Exception as e:
        logger.critical(f" Failed to send email alert. Error traceback: {e}")