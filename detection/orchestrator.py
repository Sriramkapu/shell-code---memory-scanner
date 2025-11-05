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
from utils.logging_utils import RotatingJSONLogger, aggregate_logs
from utils.security_utils import check_admin_privileges, safe_terminate_process, compute_sha256, verify_file_integrity

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
                
        except requests.exceptions.ConnectionError:
            # Elasticsearch not available - this is expected if not running
            # Silently return False to avoid cluttering output during normal operation
            return False
        except Exception as e:
            print(f"[WARNING] Error sending to Elasticsearch: {e}")
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
        """Generate PDF report from detection events with SHA256 verification"""
        if not self.enabled:
            return False
        
        # Ensure report directory exists (handle missing directories gracefully)
        try:
            os.makedirs(self.report_dir, exist_ok=True)
        except Exception as e:
            print(f"Error creating report directory: {e}")
            logger.log_error(f"Failed to create report directory: {e}")
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
            
            # Compute and store SHA256 hash for integrity verification
            report_hash = compute_sha256(output_path)
            if report_hash:
                # Store hash in a separate metadata file
                hash_file = output_path + '.sha256'
                with open(hash_file, 'w') as f:
                    f.write(f"{report_hash}  {os.path.basename(output_path)}\n")
                print(f"PDF report generated: {output_path}")
                print(f"SHA256: {report_hash}")
                return True
            else:
                print(f"PDF report generated but failed to compute hash: {output_path}")
                return True  # Still return True as report was created
            
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

# --- Agent bindings ---
# Load C agent library via ctypes (falls back to stub if unavailable)
try:
    from agent.monitor.agent_bindings import AgentCore
    agent = AgentCore()
except ImportError:
    # Fallback stub implementation
    class AgentCore:
        def dump_memory(self, pid, out_path):
            # Stub: write test pattern (NOP sled + infinite loop)
            with open(out_path, 'wb') as f:
                f.write(b'\x90\x90\x90\x90\xeb\xfe' + b'\x00' * 1018)
            return True
    agent = AgentCore()
    print("[WARNING] Using stub agent implementation (C library not available)")

# --- Import YARA scanner and disassembler ---
yara_scanner_spec = importlib.util.spec_from_file_location("yara_scanner", os.path.join(os.path.dirname(__file__), "yara_scanner.py"))
yara_scanner = importlib.util.module_from_spec(yara_scanner_spec)
yara_scanner_spec.loader.exec_module(yara_scanner)

disassembler_spec = importlib.util.spec_from_file_location("disassembler", os.path.join(os.path.dirname(__file__), "disassembler.py"))
disassembler = importlib.util.module_from_spec(disassembler_spec)
disassembler_spec.loader.exec_module(disassembler)

# Import disk scanner
from detection import disk_scanner

# --- Enhanced logging utility ---
# Initialize rotating logger
logger = RotatingJSONLogger(LOG_PATH, max_bytes=10*1024*1024, backup_count=5)

def log_detection(event):
    """Log detection event with rotating file handler"""
    try:
        logger.log_detection(event)
    except Exception as e:
        # Fallback to basic logging if rotating logger fails
        try:
            with open(LOG_PATH, 'a') as f:
                f.write(json.dumps(event) + '\n')
        except Exception as fallback_error:
            print(f"Critical: Failed to log detection event: {fallback_error}")

# --- Main orchestration ---
def main():
    parser = argparse.ArgumentParser(description="Orchestrator for memory and disk scanning.")
    parser.add_argument('--single-scan', action='store_true', help='Run a single scan and exit (for quick test)')
    parser.add_argument('--generate-report', action='store_true', help='Generate PDF report after scan')
    parser.add_argument('--rules', type=str, default=None, help='Path to YARA rules file to load (overrides default)')
    parser.add_argument('--enable-siem', action='store_true', help='Force enable SIEM integration (overrides config)')
    parser.add_argument('--disable-siem', action='store_true', help='Force disable SIEM integration (overrides config)')
    parser.add_argument('--scan-mode', type=str, choices=['memory', 'disk', 'both'], default='both', help='Scan mode: memory, disk, or both')
    parser.add_argument('--max-memory-findings', type=int, default=2, help='Maximum memory findings per scan cycle')
    parser.add_argument('--max-disk-findings', type=int, default=2, help='Maximum disk findings per scan cycle')
    parser.add_argument('--verify-integrity', action='store_true', help='Verify SHA256 integrity of reports and dumps')
    parser.add_argument('--show-stats', action='store_true', help='Show log aggregation statistics and exit')
    args = parser.parse_args()
    
    print("Loading config...")
    try:
        config = load_config()
    except FileNotFoundError:
        print(f"ERROR: Config file not found at {CONFIG_PATH}")
        logger.log_error(f"Config file not found: {CONFIG_PATH}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to load config: {e}")
        logger.log_error(f"Failed to load config: {e}", exc_info=True)
        sys.exit(1)
    
    monitored = config.get('monitored_processes', [])
    dump_path = config.get('dump_path', MEM_DUMP_DIR)
    alert_server = config.get('alert_server', None)
    scan_paths = config.get('scan_paths', [])
    scan_interval = config.get('scan_interval_seconds', 60)
    
    # Ensure required directories exist
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        os.makedirs(dump_path, exist_ok=True)
    except Exception as e:
        print(f"ERROR: Failed to create required directories: {e}")
        logger.log_error(f"Failed to create directories: {e}", exc_info=True)
        sys.exit(1)
    
    # Show log statistics if requested
    if args.show_stats:
        stats = aggregate_logs(LOG_PATH)
        print("\n=== Detection Log Statistics ===")
        print(f"Total Detections: {stats['total_detections']}")
        print(f"By Source: {stats['by_source']}")
        print(f"By Severity: {stats['by_severity']}")
        print(f"Top Rules: {dict(list(sorted(stats['by_rule'].items(), key=lambda x: x[1], reverse=True))[:10])}")
        print("\nRecent Detections:")
        for det in stats['recent_detections']:
            print(f"  - {det['timestamp']}: {det['source']} - {det['severity']} - {det['yara_match']}")
        return
    
    # Check admin privileges
    has_priv, platform_name = check_admin_privileges()
    if not has_priv:
        logger.log_warning(f"Running without administrator/root privileges on {platform_name}")
        print(f"[WARNING] Running without administrator/root privileges on {platform_name}")
        print("Some operations (e.g., process termination) may fail")
    
    # Google Drive and cloud storage removed - using Docker instead
    print("Storage: Using Docker for containerized deployment")
    
    # Initialize SIEM integration with CLI override
    print("Initializing SIEM integration...")
    siem = SIEMIntegration(config)
    
    # Apply CLI overrides
    if args.enable_siem:
        siem.enabled = True
        print("SIEM integration force-enabled via CLI")
    elif args.disable_siem:
        siem.enabled = False
        print("SIEM integration force-disabled via CLI")
    
    if siem.enabled:
        print("SIEM integration enabled")
        # Test connectivity (non-blocking)
        try:
            test_response = requests.get(f"{siem.elasticsearch_url}/_cluster/health", timeout=5)
            if test_response.status_code == 200:
                print(f"✓ Elasticsearch connection verified")
            else:
                print(f"⚠ Elasticsearch returned status {test_response.status_code}")
                logger.log_warning(f"Elasticsearch connectivity check returned status {test_response.status_code}")
        except Exception as e:
            print(f"⚠ Could not verify Elasticsearch connectivity: {e}")
            logger.log_warning(f"Elasticsearch connectivity check failed: {e}")
            # Continue anyway - SIEM failures shouldn't stop scanning
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
    
    # Check if rules file exists
    if not os.path.exists(rules_path):
        print(f"ERROR: YARA rules file not found: {rules_path}")
        logger.log_error(f"YARA rules file not found: {rules_path}")
        sys.exit(1)
    
    # Validate YARA rules integrity
    try:
        from utils.yara_validator import validate_yara_rules
        validation = validate_yara_rules(rules_path)
        if not validation['valid']:
            print(f"[WARNING] YARA rules validation warnings: {validation.get('errors', [])}")
            logger.log_warning(f"YARA rules validation warnings: {validation.get('errors', [])}")
        else:
            print(f"[OK] YARA rules validated: {validation['rule_count']} rules loaded")
            print(f"  SHA256: {validation['file_hash'][:16]}...")
    except Exception as e:
        print(f"[WARNING] YARA validation skipped: {e}")
        logger.log_warning(f"YARA validation skipped: {e}")
    
    # Load YARA rules with error handling
    try:
        import yara
        rules = yara_scanner.load_rules(rules_path)
        if rules is None:
            raise Exception("YARA rules compilation returned None")
        print(f"[OK] YARA rules compiled successfully")
    except yara.Error as e:
        print(f"ERROR: Failed to compile YARA rules: {e}")
        logger.log_error(f"Failed to compile YARA rules: {e}", exc_info=True)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to load YARA rules: {e}")
        logger.log_error(f"Failed to load YARA rules: {e}", exc_info=True)
        sys.exit(1)
    
    seen_hashes = set()
    seen_disk = set()
    all_events = []  # Collect events for reporting
    MAX_MEMORY_FINDINGS = args.max_memory_findings
    MAX_DISK_FINDINGS = args.max_disk_findings
    
    # Validate scan paths exist
    valid_scan_paths = []
    for path in scan_paths:
        if os.path.exists(path):
            valid_scan_paths.append(path)
        else:
            print(f"[WARNING] Scan path does not exist: {path}")
            logger.log_warning(f"Scan path does not exist: {path}")
    
    if not valid_scan_paths and args.scan_mode in ['disk', 'both']:
        print("[WARNING] No valid scan paths found. Disk scanning will be skipped.")
        logger.log_warning("No valid scan paths found")
    
    scan_cycle = 0
    while True:
        scan_cycle += 1
        print(f"\n=== Scan Cycle {scan_cycle} ===")
        
        # Memory scanning
        if args.scan_mode in ['memory', 'both']:
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
                
                # Ensure dump directory exists
                try:
                    os.makedirs(dump_path, exist_ok=True)
                except Exception as e:
                    print(f"[-] Failed to create dump directory: {e}")
                    logger.log_error(f"Failed to create dump directory: {e}")
                    continue
                
                if not agent.dump_memory(pid, mem_dump_file):
                    print(f"[-] Failed to dump memory for PID {pid}")
                    logger.log_warning(f"Failed to dump memory for PID {pid}")
                    continue
                
                try:
                    with open(mem_dump_file, 'rb') as f:
                        mem_bytes = f.read()
                    
                    # Compute SHA256 hash for dump file
                    dump_hash = compute_sha256(mem_dump_file)
                    if dump_hash:
                        hash_file = mem_dump_file + '.sha256'
                        with open(hash_file, 'w') as hf:
                            hf.write(f"{dump_hash}  {os.path.basename(mem_dump_file)}\n")
                except Exception as e:
                    print(f"[-] Failed to read memory dump: {e}")
                    logger.log_error(f"Failed to read memory dump: {e}")
                    continue
                try:
                    matches = rules.match(data=mem_bytes)
                except Exception as e:
                    print(f"[-] YARA scan failed for PID {pid}: {e}")
                    logger.log_error(f"YARA scan failed for PID {pid}: {e}")
                    continue
                
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
                    
                    # Safe process termination with permission checks
                    if pid != os.getpid():
                        success, action, reason = safe_terminate_process(pid, timeout=5)
                        if not success:
                            print(f"[!] Failed to terminate PID {pid}: {reason}")
                            logger.log_warning(f"Failed to terminate PID {pid}: {reason}")
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
                        "memory_entropy": memory_entropy,
                        "dump_sha256": dump_hash if 'dump_hash' in locals() else None
                    }
                    log_detection(event)
                    all_events.append(event)
                    
                    # Send to SIEM (non-blocking - failures shouldn't stop scanning)
                    if siem.enabled:
                        try:
                            siem.send_to_elasticsearch(event)
                        except Exception as e:
                            print(f"[WARNING] Failed to send to Elasticsearch: {e}")
                            logger.log_warning(f"Elasticsearch send failed: {e}")
                        
                        try:
                            siem.send_to_splunk(event)
                        except Exception as e:
                            print(f"[WARNING] Failed to send to Splunk: {e}")
                            logger.log_warning(f"Splunk send failed: {e}")
                    
                    # Real-time email notification (non-blocking)
                    try:
                        send_detection_email_notification(event)
                        print("Email notification sent for event")
                    except Exception as e:
                        print(f"[WARNING] Failed to send email notification: {e}")
                        logger.log_warning(f"Email notification failed: {e}")
                    
                    memory_findings += 1
                    if memory_findings >= MAX_MEMORY_FINDINGS:
                        print("Reached memory findings cap, stopping memory scan loop.")
                        break
                else:
                    print(f"[ ] No YARA match for PID {pid}")
        else:
            memory_findings = 0
        
        # Disk scan
        disk_count = 0
        if args.scan_mode in ['disk', 'both'] and valid_scan_paths:
            print("Starting disk scan...")
            try:
                disk_matches = disk_scanner.scan_files_with_yara(
                    valid_scan_paths,
                    rules,
                    max_results=MAX_DISK_FINDINGS,
                    exclude_rules={"PE_Signature_Quick_Check"}
                )
            except Exception as e:
                print(f"[ERROR] Disk scan failed: {e}")
                logger.log_error(f"Disk scan failed: {e}", exc_info=True)
                disk_matches = []
        else:
            disk_matches = []
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
            
            # Send to SIEM (non-blocking)
            if siem.enabled:
                try:
                    siem.send_to_elasticsearch(event)
                except Exception as e:
                    print(f"[WARNING] Failed to send to Elasticsearch: {e}")
                    logger.log_warning(f"Elasticsearch send failed: {e}")
                
                try:
                    siem.send_to_splunk(event)
                except Exception as e:
                    print(f"[WARNING] Failed to send to Splunk: {e}")
                    logger.log_warning(f"Splunk send failed: {e}")
            
            # Real-time email notification (non-blocking)
            try:
                send_detection_email_notification(event)
                print("Email notification sent for event")
            except Exception as e:
                print(f"[WARNING] Failed to send email notification: {e}")
                logger.log_warning(f"Email notification failed: {e}")
            disk_count += 1
            if disk_count >= MAX_DISK_FINDINGS:
                print("Reached disk findings cap, stopping disk scan loop.")
                break
        
        if args.scan_mode in ['disk', 'both']:
            print(f"Disk scan complete. {len(disk_matches)} detections logged.")
        
        # Generate PDF report if requested (non-blocking)
        if args.generate_report and all_events:
            print("Generating PDF report...")
            try:
                success = pdf_reporter.generate_detection_report(all_events)
                if success and args.verify_integrity:
                    # Verify report integrity
                    report_files = [f for f in os.listdir(pdf_reporter.report_dir) if f.endswith('.pdf')]
                    if report_files:
                        latest_report = os.path.join(pdf_reporter.report_dir, sorted(report_files)[-1])
                        is_valid, computed_hash, message = verify_file_integrity(latest_report)
                        print(f"Report integrity check: {message}")
                        if is_valid:
                            print(f"Report SHA256: {computed_hash}")
            except Exception as e:
                print(f"[WARNING] PDF report generation failed: {e}")
                logger.log_error(f"PDF report generation failed: {e}", exc_info=True)
        
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