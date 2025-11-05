# Integration Examples & Screenshots

## Kibana Dashboard Example

### Index Pattern Setup

**Index Pattern:** `detections`
**Time Field:** `@timestamp`

### Visualizations

#### Detection Timeline
```
Timeline View:
┌─────────────────────────────────────────────────────────┐
│ Detections Over Time                                    │
│                                                         │
│  ████                                                    │
│  ████  ████                                              │
│  ████  ████  ████                                        │
│─────────────────────────────────────────────────────────│
│ 14:00  14:30  15:00  15:30  16:00                       │
│                                                         │
│ Total: 15 detections                                     │
└─────────────────────────────────────────────────────────┘
```

#### Severity Breakdown
```
Pie Chart:
┌─────────────────────────────────────┐
│ Severity Distribution               │
│                                     │
│      🔴 Critical (20%)             │
│    ████████                         │
│  ████████████ High (40%)           │
│  ████████████                       │
│  ████████ Medium (30%)              │
│  ████ Low (10%)                     │
│                                     │
│ Total: 15 detections                 │
└─────────────────────────────────────┘
```

#### Top YARA Rules
```
Table View:
┌────────────────────────────────────┬──────────┐
│ YARA Rule                          │ Matches  │
├────────────────────────────────────┼──────────┤
│ Shellcode_Metasploit_Common        │    5     │
│ Shellcode_XOR_Decryption_Loop      │    4     │
│ Shellcode_Loader_APIs              │    3     │
│ Shellcode_NOP_Sled                │    2     │
│ Shellcode_Syscall_Setup            │    1     │
└────────────────────────────────────┴──────────┘
```

### Kibana Query Example

```json
GET /detections/_search
{
  "query": {
    "bool": {
      "must": [
        {
          "match": {
            "severity": "High"
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": "now-24h"
            }
          }
        }
      ]
    }
  },
  "sort": [
    {
      "@timestamp": "desc"
    }
  ],
  "size": 50
}
```

## PDF Report Sample

### Report Structure

```
┌─────────────────────────────────────────────────────────┐
│           Memory Shellcode Detection Report             │
│                                                         │
│ Detection Summary                                       │
│ ┌─────────────────────────────┬──────────────────────┐ │
│ │ Total Detections            │          15          │ │
│ │ Memory Detections           │          10         │ │
│ │ Disk Detections             │           5         │ │
│ │ Report Generated            │ 2025-01-17 14:30:22 │ │
│ └─────────────────────────────┴──────────────────────┘ │
│                                                         │
│ Detailed Detections                                     │
│ ┌──────────┬────────┬──────────┬──────────┬──────────┐ │
│ │ Timestamp│ Source │ Process  │ YARA     │ Severity │ │
│ ├──────────┼────────┼──────────┼──────────┼──────────┤ │
│ │ 14:30:22 │ Memory │python.exe│Metasploit│   High   │ │
│ │ 14:25:15 │ Memory │svchost   │XOR Loop  │  Medium  │ │
│ │ 14:20:08 │ Disk   │susp.exe  │Loader    │ Critical │ │
│ └──────────┴────────┴──────────┴──────────┴──────────┘ │
│                                                         │
│ SHA256: a1b2c3d4e5f6...                                │
└─────────────────────────────────────────────────────────┘
```

### Report File Structure

```
reports/
├── detection_report_20250117_143022.pdf
├── detection_report_20250117_143022.pdf.sha256
├── detection_report_20250117_120000.pdf
└── detection_report_20250117_120000.pdf.sha256
```

## HTML Email Alert Example

### Email Structure

```
Subject: 🚨 SECURITY ALERT (Memory): Shellcode_Metasploit_Common_Patterns

┌─────────────────────────────────────────────────────────┐
│  🛡️ Memory Shellcode Detection                         │
│     Enterprise Security Alert System                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  🚨 SECURITY ALERT DETECTED 🚨                         │
│                                                         │
│  Detection Summary                                      │
│  ┌─────────────────┬─────────────────────────────────┐ │
│  │ Detection Source│ Memory                           │ │
│  │ Severity Level  │ 🔴 High                          │ │
│  │ Detection Time  │ 2025-01-17 14:30:22 IST         │ │
│  │ Action Taken    │ Blocked (terminated)             │ │
│  └─────────────────┴─────────────────────────────────┘ │
│                                                         │
│  🔍 YARA Pattern Matches                                │
│  ┌───────────────────────────────────────────────────┐ │
│  │ Rule: Shellcode_Metasploit_Common_Patterns       │ │
│  │ Description: Metasploit framework shellcode      │ │
│  │ Category: Shellcode                              │ │
│  │ Severity: High                                   │ │
│  │                                                  │ │
│  │ String Matches:                                 │ │
│  │ ┌──────┬────────┬────────┬──────────┬──────────┐│ │
│  │ │ ID   │ Offset │ Length │ ASCII    │ Hex      ││ │
│  │ ├──────┼────────┼────────┼──────────┼──────────┤│ │
│  │ │$prol │ 1024   │ 15     │ \xfc\xe8 │ fce80000 ││ │
│  │ └──────┴────────┴────────┴──────────┴──────────┘│ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  📋 Detailed Information                                │
│  ┌─────────────────┬─────────────────────────────────┐ │
│  │ Process Name    │ python.exe                      │ │
│  │ Process ID      │ 1234                            │ │
│  │ Memory Hash     │ 0x1a2b3c4d5e6f                  │ │
│  │ Memory Entropy  │ 7.89                            │ │
│  │ Dump File       │ /quarantine/1234_mem.dump      │ │
│  └─────────────────┴─────────────────────────────────┘ │
│                                                         │
│  System Information:                                    │
│  Host: workstation-01 | OS: Windows 10                  │
│                                                         │
│  Generated at: 2025-01-17 14:30:25 IST                  │
└─────────────────────────────────────────────────────────┘
```

## Log Entry Example

### JSONL Log Format

```json
{
  "timestamp": "2025-01-17T14:30:22.123456+00:00",
  "source": "memory",
  "host": "workstation-01",
  "process": "python.exe",
  "pid": 1234,
  "yara_match": ["Shellcode_Metasploit_Common_Patterns"],
  "yara_details": [
    {
      "rule": "Shellcode_Metasploit_Common_Patterns",
      "meta": {
        "description": "Metasploit framework shellcode patterns",
        "severity": "High",
        "category": "Shellcode"
      },
      "strings": [
        {
          "id": "$prologue",
          "offset": 1024,
          "length": 15,
          "ascii": "\\xfc\\xe8\\x00\\x00\\x00\\x00\\x60\\x89\\xe5\\x31\\xc0\\x64\\x8b\\x50\\x30",
          "hex": "fce800000000006089e531c0648b5030"
        }
      ]
    }
  ],
  "severity": "High",
  "action": "Blocked (terminated)",
  "memory_region_hash": "0x1a2b3c4d5e6f",
  "dump_path": "/quarantine/1234_mem.dump",
  "memory_entropy": 7.89,
  "dump_sha256": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
}
```

## Complete Pipeline Flow Visualization

```
┌─────────────────────────────────────────────────────────────┐
│                    Detection Event Flow                     │
└─────────────────────────────────────────────────────────────┘

1. Detection Event Generated
   ├─ Process: python.exe (PID 1234)
   ├─ YARA Match: Shellcode_Metasploit_Common_Patterns
   ├─ Severity: High
   └─ Action: Terminated
   
2. Logged to JSONL
   ├─ File: logs/detections.jsonl
   ├─ Format: JSON Lines
   └─ Rotation: 10MB files, 5 backups
   
3. Email Alert Sent
   ├─ Subject: 🚨 SECURITY ALERT (Memory): Shellcode_Metasploit...
   ├─ Format: HTML + Text fallback
   ├─ Recipients: admin@company.com
   └─ Delivery: ~1-2 seconds
   
4. Sent to SIEM (Elasticsearch)
   ├─ Endpoint: http://elasticsearch:9200/detections/_doc
   ├─ Index: detections
   ├─ Status: 201 Created
   └─ Latency: ~50ms
   
5. Indexed in Kibana
   ├─ Index Pattern: detections
   ├─ Visualization: Timeline, Severity, Top Rules
   └─ Query: Real-time updates
   
6. PDF Report Generated (if requested)
   ├─ File: reports/detection_report_20250117_143022.pdf
   ├─ SHA256: a1b2c3d4e5f6...
   └─ Generation Time: ~2-3 seconds
```

## Command-Line Examples

### Complete Detection Flow

```bash
# 1. Start full stack with SIEM
docker-compose up -d

# 2. Run single scan with report generation
python detection/orchestrator.py --single-scan --generate-report --verify-integrity

# 3. View log statistics
python detection/orchestrator.py --show-stats

# 4. View log dashboard
python utils/log_dashboard.py

# 5. Filter by severity
python utils/log_dashboard.py --filter-severity High

# 6. Access Kibana dashboard
# Open http://localhost:5601 in browser
```

### Non-Privileged Mode Example

```bash
# Read-only mode (no memory scanning, no process termination)
docker run --rm \
  --read-only \
  --tmpfs /tmp \
  --tmpfs /quarantine \
  detection-engine \
  python detection/orchestrator.py \
    --scan-mode disk \
    --show-stats \
    --disable-siem
```

## Integration Testing Example

```bash
# 1. Create test malware file
echo "THIS_IS_A_TEST_MALWARE_FILE" > test_malware.txt

# 2. Run detection
python detection/orchestrator.py --single-scan --generate-report

# 3. Verify detection logged
python detection/orchestrator.py --show-stats

# 4. Check email sent (if configured)

# 5. Verify SIEM entry (if enabled)
curl http://localhost:9200/detections/_search?q=severity:High

# 6. Verify PDF report generated
ls -lh reports/*.pdf

# 7. Verify SHA256 hash
cat reports/detection_report_*.pdf.sha256
```

