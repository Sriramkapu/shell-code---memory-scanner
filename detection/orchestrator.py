# orchestrator.py
# Integrates agent, YARA scanner, disassembler, and logging
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import yaml
import json
import time
import psutil
import importlib.util
from datetime import datetime, timezone
import subprocess
import disk_scanner
import argparse
from utils.email_notifier import send_email_notification

print("Orchestrator script started")
# --- Load config ---
CONFIG_PATH = os.path.join(os.path.dirname(__file__), '../config/agent_config.yaml')
LOG_PATH = os.path.join(os.path.dirname(__file__), '../logs/detections.jsonl')
YARA_RULES_PATH = os.path.join(os.path.dirname(__file__), '../config/yara_rules/sample_shellcode.yar')
MEM_DUMP_DIR = '/quarantine/'

# --- Ensure log and dump dirs exist ---
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
os.makedirs(MEM_DUMP_DIR, exist_ok=True)

# --- Load config ---
def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)

# --- Agent bindings (stub) ---
# In real use, load the compiled agent_core shared library via ctypes/cffi
class AgentCore:
    def dump_memory(self, pid, out_path):
        # TODO: Call C function via ctypes/cffi
        # For now, stub: write test pattern (NOP sled + infinite loop)
        with open(out_path, 'wb') as f:
            f.write(b'\x90\x90\x90\x90\xeb\xfe' + b'\x00' * 1018)
        return True

agent = AgentCore()

# --- Import YARA scanner and disassembler ---
yara_scanner_spec = importlib.util.spec_from_file_location("yara_scanner", os.path.join(os.path.dirname(__file__), "yara_scanner.py"))
yara_scanner = importlib.util.module_from_spec(yara_scanner_spec)
yara_scanner_spec.loader.exec_module(yara_scanner)

disassembler_spec = importlib.util.spec_from_file_location("disassembler", os.path.join(os.path.dirname(__file__), "disassembler.py"))
disassembler = importlib.util.module_from_spec(disassembler_spec)
disassembler_spec.loader.exec_module(disassembler)

# --- Logging utility ---
def log_detection(event):
    with open(LOG_PATH, 'a') as f:
        f.write(json.dumps(event) + '\n')

# --- Main orchestration ---
def main():
    parser = argparse.ArgumentParser(description="Orchestrator for memory and disk scanning.")
    parser.add_argument('--single-scan', action='store_true', help='Run a single scan and exit (for quick test)')
    args = parser.parse_args()
    print("Loading config...")
    config = load_config()
    monitored = config.get('monitored_processes', [])
    dump_path = config.get('dump_path', MEM_DUMP_DIR)
    alert_server = config.get('alert_server', None)
    scan_paths = config.get('scan_paths', [])
    scan_interval = config.get('scan_interval_seconds', 60)
    print("Compiling YARA rules...")
    rules = yara_scanner.load_rules(YARA_RULES_PATH)
    seen_hashes = set()
    seen_disk = set()
    while True:
        print("Starting process scan...")
        detection_count = 0
        max_detections = 1  # Only log one detection for fastest test
        for proc in psutil.process_iter(['pid', 'name']):
            print(f"Checking process: {proc.info}")
            if proc.info['name'] not in monitored:
                continue
            pid = proc.info['pid']
            pname = proc.info['name']
            mem_dump_file = os.path.join(dump_path, f"{pid}_mem.dump")
            print(f"[+] Dumping memory for {pname} (PID {pid})...")
            if not agent.dump_memory(pid, mem_dump_file):
                print(f"[-] Failed to dump memory for PID {pid}")
                continue
            with open(mem_dump_file, 'rb') as f:
                mem_bytes = f.read()
            matches = rules.match(data=mem_bytes)
            if matches:
                print(f"[!] YARA match in PID {pid}: {matches}")
                print(f"[>] Disassembling suspicious region...")
                disassembler.disassemble_bytes(mem_bytes[:64], base_addr=0x1000)
                mem_hash = hex(hash(mem_bytes))
                dedup_key = (pid, mem_hash, tuple(sorted([m.rule for m in matches])))
                if dedup_key in seen_hashes:
                    print(f"[=] Duplicate detection for PID {pid}, skipping log/alert.")
                    continue
                seen_hashes.add(dedup_key)
                # Real blocking: terminate the process, but skip self-termination
                if pid != os.getpid():
                    try:
                        psutil.Process(pid).kill()
                        action = "Blocked (terminated)"
                    except Exception as e:
                        print(f"[!] Failed to terminate PID {pid}: {e}")
                        action = "Blocked (stub)"
                else:
                    print("[!] Skipping self-termination to allow notification.")
                    action = "Blocked (would terminate self)"
                event = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "memory",
                    "host": os.uname().nodename if hasattr(os, 'uname') else 'localhost',
                    "process": pname,
                    "pid": pid,
                    "yara_match": [m.rule for m in matches],
                    "severity": "Medium",
                    "action": action,
                    "memory_region_hash": mem_hash,
                    "dump_path": mem_dump_file
                }
                log_detection(event)
                # Real-time email notification
                subject = f"YARA Match Detected (Memory): {event['yara_match']}"
                body = f"Detection event:\n\n{json.dumps(event, indent=2)}"
                print("Attempting to send email notification for event:", event)
                try:
                    send_email_notification(subject, body)
                    print("Email notification sent for event:", event)
                except Exception as e:
                    print("Failed to send email notification for event:", event, e)
                # TODO: Add SIEM/ELK output and PDF reporting here
                detection_count += 1
                if detection_count >= max_detections:
                    print("Max detections reached, exiting loop.")
                    break
            else:
                print(f"[ ] No YARA match for PID {pid}")
        # Disk scan
        print("Starting disk scan...")
        disk_matches = disk_scanner.scan_files_with_yara(scan_paths, rules)
        for event in disk_matches:
            # Deduplication for disk: file_path + yara_match
            dedup_key = (event['file_path'], tuple(sorted(event['yara_match'])))
            if dedup_key in seen_disk:
                print(f"[=] Duplicate disk detection for {event['file_path']}, skipping log/alert.")
                continue
            seen_disk.add(dedup_key)
            event['source'] = 'disk'
            log_detection(event)
            # Real-time email notification
            subject = f"YARA Match Detected (Disk): {event['yara_match']}"
            body = f"Detection event:\n\n{json.dumps(event, indent=2)}"
            print("Attempting to send email notification for event:", event)
            try:
                send_email_notification(subject, body)
                print("Email notification sent for event:", event)
            except Exception as e:
                print("Failed to send email notification for event:", event, e)
            # TODO: Add SIEM/ELK output and PDF reporting here
        print(f"Disk scan complete. {len(disk_matches)} detections logged.")
        if args.single_scan:
            print("Single scan mode enabled. Exiting after one scan loop.")
            break
        print(f"Sleeping for {scan_interval} seconds before next scan...")
        time.sleep(scan_interval)

if __name__ == "__main__":
    main()

import subprocess
import sys
import os

def run_orchestrator():
    # Run the orchestrator script
    result = subprocess.run(
        [sys.executable, os.path.join('detection', 'orchestrator.py')],
        capture_output=True, text=True
    )
    print("STDOUT:\n", result.stdout)
    print("STDERR:\n", result.stderr)
    assert result.returncode == 0, "Orchestrator did not exit cleanly"

def check_log():
    log_path = os.path.join('logs', 'detections.jsonl')
    assert os.path.exists(log_path), "Log file not found"
    with open(log_path) as f:
        lines = f.readlines()
        print("Log entries:")
        for line in lines:
            print(line.strip())
    assert len(lines) > 0, "No detection events logged"

if __name__ == "__main__":
    run_orchestrator()
    check_log() 