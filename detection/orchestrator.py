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
import argparse
import requests
from utils.email_notifier import send_email_notification, send_detection_email_notification

print("Orchestrator script started")

# --- Load config ---
CONFIG_PATH = os.path.join(os.path.dirname(__file__), '../config/agent_config.yaml')
LOG_PATH = os.path.join(os.path.dirname(__file__), '../logs/detections.jsonl')
YARA_RULES_PATH = os.path.join(os.path.dirname(__file__), '../config/yara_rules/sample_shellcode.yar')
MEM_DUMP_DIR = '/quarantine/'

# --- Ensure log and dump dirs exist ---
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
os.makedirs(MEM_DUMP_DIR, exist_ok=True)

# --- SIEM/ELK Integration ---
class SIEMIntegration:
    def __init__(self, config):
        self.config = config.get('siem', {})
        self.enabled = self.config.get('enabled', False)
        self.elasticsearch_url = self.config.get('elasticsearch_url')
        self.kibana_url = self.config.get('kibana_url')
        self.index_name = self.config.get('index_name', 'detections')
        
    def send_to_elasticsearch(self, event):
        """Send detection event to Elasticsearch"""
        if not self.enabled or not self.elasticsearch_url:
            return False
            
        try:
            # Add timestamp for Elasticsearch
            event['@timestamp'] = event.get('timestamp', datetime.now(timezone.utc).isoformat())
            
            # Send to Elasticsearch
            response = requests.post(
                f"{self.elasticsearch_url}/{self.index_name}/_doc",
                json=event,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                print(f"Event sent to Elasticsearch: {event.get('yara_match', [])}")
                return True
            else:
                print(f"Failed to send to Elasticsearch: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"Error sending to Elasticsearch: {e}")
            return False
    
    def send_to_splunk(self, event):
        """Send detection event to Splunk HEC"""
        splunk_config = self.config.get('splunk', {})
        if not splunk_config.get('enabled'):
            return False
            
        try:
            splunk_url = splunk_config.get('hec_url')
            splunk_token = splunk_config.get('hec_token')
            
            if not splunk_url or not splunk_token:
                return False
                
            headers = {
                'Authorization': f'Splunk {splunk_token}',
                'Content-Type': 'application/json'
            }
            
            # Format for Splunk
            splunk_event = {
                'event': event,
                'sourcetype': 'detection_events',
                'source': 'memory_shellcode_detector'
            }
            
            response = requests.post(
                splunk_url,
                json=splunk_event,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"Event sent to Splunk: {event.get('yara_match', [])}")
                return True
            else:
                print(f"Failed to send to Splunk: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"Error sending to Splunk: {e}")
            return False

# --- PDF Reporting ---
class PDFReporter:
    def __init__(self, config):
        self.config = config.get('reporting', {})
        self.enabled = self.config.get('enabled', False)
        self.report_dir = self.config.get('report_dir', '../reports')
        
        # Ensure report directory exists
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_detection_report(self, events, output_path=None):
        """Generate PDF report from detection events"""
        if not self.enabled:
            return False
            
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = os.path.join(self.report_dir, f"detection_report_{timestamp}.pdf")
            
            # Create PDF document
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            story = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=16,
                spaceAfter=30
            )
            story.append(Paragraph("Memory Shellcode Detection Report", title_style))
            story.append(Spacer(1, 12))
            
            # Summary
            story.append(Paragraph("Detection Summary", styles['Heading2']))
            story.append(Spacer(1, 12))
            
            summary_data = [
                ['Total Detections', str(len(events))],
                ['Memory Detections', str(len([e for e in events if e.get('source') == 'memory']))],
                ['Disk Detections', str(len([e for e in events if e.get('source') == 'disk']))],
                ['Report Generated', datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
            ]
            
            summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 12))
            
            # Detailed detections
            story.append(Paragraph("Detailed Detections", styles['Heading2']))
            story.append(Spacer(1, 12))
            
            if events:
                # Create table headers
                headers = ['Timestamp', 'Source', 'Process/File', 'YARA Match', 'Severity', 'Action']
                table_data = [headers]
                
                for event in events:
                    table_data.append([
                        event.get('timestamp', '')[:19],  # Truncate timestamp
                        event.get('source', ''),
                        event.get('process', event.get('file_path', ''))[:30],  # Truncate long names
                        ', '.join(event.get('yara_match', []))[:30],
                        event.get('severity', ''),
                        event.get('action', '')
                    ])
                
                # Create table
                detection_table = Table(table_data, colWidths=[1.2*inch, 0.8*inch, 1.5*inch, 1.5*inch, 0.8*inch, 1.2*inch])
                detection_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                story.append(detection_table)
            
            # Build PDF
            doc.build(story)
            print(f"PDF report generated: {output_path}")
            return True
            
        except ImportError:
            print("ReportLab not installed. Install with: pip install reportlab")
            return False
        except Exception as e:
            print(f"Error generating PDF report: {e}")
            return False

# --- Load config ---
def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)

# Google Drive and cloud storage removed - using Docker instead

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

# Import disk scanner
from detection import disk_scanner

# --- Logging utility ---
def log_detection(event):
    with open(LOG_PATH, 'a') as f:
        f.write(json.dumps(event) + '\n')

# --- Main orchestration ---
def main():
    parser = argparse.ArgumentParser(description="Orchestrator for memory and disk scanning.")
    parser.add_argument('--single-scan', action='store_true', help='Run a single scan and exit (for quick test)')
    parser.add_argument('--generate-report', action='store_true', help='Generate PDF report after scan')
    parser.add_argument('--rules', type=str, default=None, help='Path to YARA rules file to load (overrides default)')
    args = parser.parse_args()
    
    print("Loading config...")
    config = load_config()
    monitored = config.get('monitored_processes', [])
    dump_path = config.get('dump_path', MEM_DUMP_DIR)
    alert_server = config.get('alert_server', None)
    scan_paths = config.get('scan_paths', [])
    scan_interval = config.get('scan_interval_seconds', 60)
    
    # Google Drive and cloud storage removed - using Docker instead
    print("Storage: Using Docker for containerized deployment")
    
    # Initialize SIEM integration
    print("Initializing SIEM integration...")
    siem = SIEMIntegration(config)
    if siem.enabled:
        print("SIEM integration enabled")
    else:
        print("SIEM integration not enabled")
    
    # Initialize PDF reporting
    print("Initializing PDF reporting...")
    pdf_reporter = PDFReporter(config)
    if pdf_reporter.enabled:
        print("PDF reporting enabled")
    else:
        print("PDF reporting not enabled")
    
    print("Validating and compiling YARA rules...")
    rules_path = args.rules if args.rules else YARA_RULES_PATH
    
    # Validate YARA rules integrity
    try:
        from utils.yara_validator import validate_yara_rules
        validation = validate_yara_rules(rules_path)
        if not validation['valid']:
            print(f"⚠️  YARA rules validation warnings: {validation.get('errors', [])}")
        else:
            print(f"✓ YARA rules validated: {validation['rule_count']} rules loaded")
            print(f"  SHA256: {validation['file_hash'][:16]}...")
    except Exception as e:
        print(f"⚠️  YARA validation skipped: {e}")
    
    rules = yara_scanner.load_rules(rules_path)
    seen_hashes = set()
    seen_disk = set()
    all_events = []  # Collect events for reporting
    MAX_MEMORY_FINDINGS = 3
    MAX_DISK_FINDINGS = 2
    
    while True:
        print("Starting process scan...")
        memory_findings = 0
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
            # Filter out low-signal-only PE header rule from alerts
            filtered_matches = [m for m in matches if m.rule != 'PE_Signature_Quick_Check'] if matches else []
            if filtered_matches:
                print(f"[!] YARA match in PID {pid}: {matches}")
                print(f"[>] Disassembling suspicious region...")
                disassembler.disassemble_bytes(mem_bytes[:64], base_addr=0x1000)
                mem_hash = hex(hash(mem_bytes))
                dedup_key = (pid, mem_hash, tuple(sorted([m.rule for m in filtered_matches])))
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
                # Build explainable details from YARA meta and string matches
                yara_details = []
                severities = []
                for m in filtered_matches:
                    meta = getattr(m, 'meta', {}) or {}
                    # Collect string hits with offsets, ascii and hex previews
                    string_hits = []
                    for s in getattr(m, 'strings', []) or []:
                        try:
                            off, ident, data = s
                            preview_bytes = data[:32] if isinstance(data, (bytes, bytearray)) else bytes(str(data), 'latin-1', 'ignore')[:32]
                            string_hits.append({
                                "id": ident,
                                "offset": int(off),
                                "length": len(data) if hasattr(data, '__len__') else None,
                                "ascii": (data.decode('latin-1', errors='ignore') if isinstance(data, (bytes, bytearray)) else str(data))[:64],
                                "hex": preview_bytes.hex()
                            })
                        except Exception:
                            continue
                    detail = {
                        "rule": m.rule,
                        "meta": meta,
                        "strings": string_hits
                    }
                    yara_details.append(detail)
                    sev = (meta.get('severity') or '').title()
                    if sev in ["Low", "Medium", "High", "Critical"]:
                        severities.append(sev)

                # Compute event severity: max by rank if present, else Medium
                rank = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
                event_severity = "Medium"
                if severities:
                    event_severity = max(severities, key=lambda s: rank.get(s, 1))

                # Compute simple entropy on dumped memory bytes
                try:
                    from collections import Counter as _Counter
                    import math as _math
                    sample = mem_bytes[:8192]
                    freq = _Counter(sample)
                    total = float(len(sample)) if sample else 1.0
                    ent = 0.0
                    for c in freq.values():
                        p = c / total
                        ent -= p * _math.log(p, 2)
                    memory_entropy = round(ent, 3)
                except Exception:
                    memory_entropy = None

                event = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "memory",
                    "host": os.uname().nodename if hasattr(os, 'uname') else 'localhost',
                    "process": pname,
                    "pid": pid,
                    "yara_match": [m.rule for m in filtered_matches],
                    "yara_details": yara_details,
                    "severity": event_severity,
                    "action": action,
                    "memory_region_hash": mem_hash,
                    "dump_path": mem_dump_file,
                    "memory_entropy": memory_entropy
                }
                log_detection(event)
                all_events.append(event)
                
                # Send to SIEM
                if siem.enabled:
                    siem.send_to_elasticsearch(event)
                    siem.send_to_splunk(event)
                
                # Real-time email notification
                try:
                    send_detection_email_notification(event)
                    print("Email notification sent for event:", event)
                except Exception as e:
                    print("Failed to send email notification for event:", event, e)
                
                memory_findings += 1
                if memory_findings >= MAX_MEMORY_FINDINGS:
                    print("Reached memory findings cap, stopping memory scan loop.")
                    break
            else:
                print(f"[ ] No YARA match for PID {pid}")
        # Disk scan
        print("Starting disk scan...")
        disk_matches = disk_scanner.scan_files_with_yara(
            scan_paths,
            rules,
            max_results=MAX_DISK_FINDINGS,
            exclude_rules={"PE_Signature_Quick_Check"}
        )
        disk_count = 0
        for event in disk_matches:
            # Deduplication for disk: file_path + yara_match
            dedup_key = (event['file_path'], tuple(sorted(event['yara_match'])))
            if dedup_key in seen_disk:
                print(f"[=] Duplicate disk detection for {event['file_path']}, skipping log/alert.")
                continue
            seen_disk.add(dedup_key)
            event['source'] = 'disk'
            log_detection(event)
            all_events.append(event)
            
            # Send to SIEM
            if siem.enabled:
                siem.send_to_elasticsearch(event)
                siem.send_to_splunk(event)
            
            # Real-time email notification
            try:
                send_detection_email_notification(event)
                print("Email notification sent for event:", event)
            except Exception as e:
                print("Failed to send email notification for event:", event, e)
            disk_count += 1
            if disk_count >= MAX_DISK_FINDINGS:
                print("Reached disk findings cap, stopping disk scan loop.")
                break
        
        print(f"Disk scan complete. {len(disk_matches)} detections logged.")
        
        # Generate PDF report if requested
        if args.generate_report and all_events:
            print("Generating PDF report...")
            pdf_reporter.generate_detection_report(all_events)
        
        # Stop entire scanning once caps are reached in this cycle
        if memory_findings >= MAX_MEMORY_FINDINGS or disk_count >= MAX_DISK_FINDINGS:
            print("Global findings cap reached. Stopping orchestrator.")
            break
        # Exit if single scan mode
        if args.single_scan:
            print("Single scan complete. Exiting.")
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