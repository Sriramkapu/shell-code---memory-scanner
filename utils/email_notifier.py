import smtplib
from email.mime.text import MIMEText
import yaml
import os
import traceback

def load_email_config():
    config_path = os.path.join(os.path.dirname(__file__), '../config/agent_config.yaml')
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    return config.get('email', {})

def send_email_notification(subject, body):
    email_cfg = load_email_config()
    smtp_server = email_cfg.get('smtp_server')
    smtp_port = email_cfg.get('smtp_port', 587)
    smtp_user = email_cfg.get('smtp_user')
    smtp_password = email_cfg.get('smtp_password')
    recipients = email_cfg.get('recipients', [])
    if not (smtp_server and smtp_user and smtp_password and recipients):
        print('Email config incomplete, cannot send notification.')
        return
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = ', '.join(recipients)
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, recipients, msg.as_string())
        print('Email notification sent!')
    except Exception as e:
        print('Failed to send email notification:', e)
        traceback.print_exc() 