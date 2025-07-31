import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.email_notifier import send_email_notification

send_email_notification("Test Subject", "This is a test email from your malware scanner.") 