print("Test script started")
import subprocess
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import json
import smtplib
from email.mime.text import MIMEText
from utils.email_notifier import send_email_notification

def run_orchestrator():
    print("Running orchestrator...")
    try:
        result = subprocess.run(
            [sys.executable, os.path.join('detection', 'orchestrator.py')],
            capture_output=True, text=True, timeout=5
        )
        print("STDOUT:\n", result.stdout)
        print("STDERR:\n", result.stderr)
        print("Orchestrator return code:", result.returncode)
        assert result.returncode == 0, "Orchestrator did not exit cleanly"
    except subprocess.TimeoutExpired:
        print("Orchestrator timed out after 5 seconds.")

def check_log(max_entries=4, yara_match_filter="Test_NOP_Sled"):
    print("Checking log file...")
    log_path = os.path.join('logs', 'detections.jsonl')
    if not os.path.exists(log_path):
        print("Log file not found at", log_path)
        return
    with open(log_path) as f:
        lines = f.readlines()
        filtered = []
        for line in lines:
            try:
                entry = json.loads(line)
                if yara_match_filter in entry.get("yara_match", []):
                    filtered.append(entry)
            except Exception as e:
                print("Error parsing log entry:", e)
        print(f"Filtered log entries with yara_match '{yara_match_filter}':")
        for i, entry in enumerate(filtered[:max_entries]):
            print(json.dumps(entry, indent=2))
        if len(filtered) > max_entries:
            print(f"...and {len(filtered) - max_entries} more entries not shown.")
        if filtered:
            print(f"[NOTIFICATION] {len(filtered)} entries found with yara_match '{yara_match_filter}'!")
            # Send email notification
            subject = f"YARA Match Detected: {yara_match_filter}"
            body = f"YARA match detected in the following entries:\n\n" + '\n'.join(json.dumps(e, indent=2) for e in filtered[:max_entries])
            send_email_notification(subject, body)
        else:
            print(f"No entries found with yara_match '{yara_match_filter}'")
    if len(lines) == 0:
        print("No detection events logged")
    else:
        print(f"{len(lines)} detection event(s) logged.")

if __name__ == "__main__":
    try:
        run_orchestrator()
    except Exception as e:
        print("Exception occurred:", e)
    check_log()