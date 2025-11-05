# Troubleshooting Guide

## Issue 1: Elasticsearch Connection Error

### Problem
```
Error sending to Elasticsearch: HTTPConnectionPool(host='localhost', port=9200): 
Max retries exceeded with url: /detections/_doc 
(Caused by NewConnectionError: Failed to establish a new connection: 
[WinError 10061] No connection could be made because the target machine actively refused it')
```

### Explanation
The orchestrator is configured to send detection events to Elasticsearch, but Elasticsearch is not running on your machine. This is **expected behavior** when Elasticsearch isn't available.

### Solutions

#### Option 1: Disable SIEM Integration (Recommended for Local Testing)
If you don't need SIEM integration for local testing, disable it:

**Via Command Line:**
```bash
py detection/orchestrator.py --single-scan --disable-siem
```

**Via Configuration:**
Edit `config/agent_config.yaml`:
```yaml
siem:
  enabled: false  # Change from true to false
```

#### Option 2: Start Elasticsearch (For Full SIEM Integration)

**Using Docker Compose (Recommended):**
```bash
# Start Elasticsearch and Kibana
docker-compose up -d elasticsearch kibana

# Wait for services to be healthy (about 30-60 seconds)
docker-compose ps

# Then run your orchestrator
py detection/orchestrator.py --single-scan
```

**Using Docker Directly:**
```bash
docker run -d \
  --name elasticsearch \
  -p 9200:9200 \
  -p 9300:9300 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  docker.elastic.co/elasticsearch/elasticsearch:8.11.0
```

**Note:** The error message has been improved to be less alarming. Connection errors are now handled silently when Elasticsearch is not available.

---

## Issue 2: Limited Number of Alerts

### Problem
Why only 1 memory alert and 2 disk alerts?

### Explanation
The orchestrator has **findings caps** to prevent overwhelming the system and alert fatigue:

- **Memory Findings Cap:** Default = **3** per scan cycle
- **Disk Findings Cap:** Default = **2** per scan cycle

This means:
- If it finds 1 memory detection → Shows 1 alert (could show up to 3)
- If it finds 2 disk detections → Shows 2 alerts (stops at the cap of 2)

### Solutions

#### Option 1: Increase Limits via Command Line
```bash
# Increase memory findings to 10
py detection/orchestrator.py --single-scan --max-memory-findings 10

# Increase disk findings to 10
py detection/orchestrator.py --single-scan --max-disk-findings 10

# Increase both
py detection/orchestrator.py --single-scan --max-memory-findings 10 --max-disk-findings 10
```

#### Option 2: Remove Limits (Use -1 for Unlimited)
Edit `detection/orchestrator.py` to change defaults:
```python
parser.add_argument('--max-memory-findings', type=int, default=-1, help='Maximum memory findings per scan cycle (-1 for unlimited)')
parser.add_argument('--max-disk-findings', type=int, default=-1, help='Maximum disk findings per scan cycle (-1 for unlimited)')
```

Then update the logic to handle -1 as unlimited:
```python
MAX_MEMORY_FINDINGS = args.max_memory_findings if args.max_memory_findings > 0 else float('inf')
MAX_DISK_FINDINGS = args.max_disk_findings if args.max_disk_findings > 0 else float('inf')
```

#### Option 3: Check All Detections (Regardless of Caps)
The detections are still **logged to the JSONL file** even if alerts are capped. Check the log file:

```bash
# View all detections
python utils/log_dashboard.py

# View stats
py detection/orchestrator.py --show-stats

# View log file directly
type logs\detections.jsonl
```

---

## Current Default Limits

| Type | Default Limit | CLI Flag |
|------|---------------|----------|
| Memory Findings | 3 per cycle | `--max-memory-findings N` |
| Disk Findings | 2 per cycle | `--max-disk-findings N` |

## Why Limits Exist

1. **Performance:** Prevents system overload from processing too many detections
2. **Alert Fatigue:** Prevents overwhelming security teams with alerts
3. **Resource Management:** Limits memory and CPU usage during scanning
4. **Deduplication:** Works with deduplication to prevent duplicate alerts

## Best Practices

1. **For Testing:** Use higher limits (10-20) to see all detections
2. **For Production:** Keep default limits to prevent alert fatigue
3. **For Investigation:** Check log files directly to see all detections
4. **For SIEM:** All detections are logged; SIEM can query all events

---

## Summary

- **Elasticsearch Error:** Expected when Elasticsearch isn't running. Use `--disable-siem` for local testing.
- **Limited Alerts:** By design to prevent alert fatigue. Increase with `--max-memory-findings` and `--max-disk-findings` flags.
- **All Detections Logged:** Even if alerts are capped, all detections are logged to `logs/detections.jsonl`.

---

## Quick Fixes

**Disable SIEM and increase limits:**
```bash
py detection/orchestrator.py --single-scan --disable-siem --max-memory-findings 10 --max-disk-findings 10
```

**View all logged detections:**
```bash
py detection/orchestrator.py --show-stats
```

