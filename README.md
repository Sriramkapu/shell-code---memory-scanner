# Memory Shellcode Detection Framework

Enterprise-grade, multi-layered memory shellcode detection and response system with real-time monitoring, Docker containerization, and automated reporting.

## ✅ Current Project Status

- All automated tests are passing locally: 16 passed, 1 warning (PyTest return-not-none) as of 2025-10-16.
- YARA rules updated: removed undefined reference and improved literal string matching.
- Disk scanner hardened: reliable matching via filepath with safe in-memory fallback.
- Orchestrator runs end-to-end with `--single-scan`; Docker containerization for easy deployment; SIEM/email behave gracefully when not fully configured.

## 🚀 Features

### Core Detection
- **Real-time Memory Scanning**: Cross-platform process memory analysis using YARA rules
- **Shellcode Pattern Detection**: Advanced disassembly with pattern recognition for call-pop, xor loops, stack pivots, and more
- **Disk Scanning**: File-based detection with executable analysis
- **Process Monitoring**: Live process hooking and syscall tracing

### Integration & Reporting
- **Docker Containerization**: Fully containerized deployment with auto mode for continuous monitoring
- **SIEM Integration**: Elasticsearch and Splunk HEC integration
- **Email Alerts**: Real-time SMTP-based notifications with **professional HTML formatting**
- **PDF Reporting**: Automated detection reports with detailed analysis and **local timezone display**
- **Logging**: Structured JSON logging with deduplication

### Security Features
- **Process Termination**: Automatic malicious process blocking
- **Memory Dumping**: Quarantine suspicious memory regions
- **Cross-Platform**: Windows, Linux, and macOS support
- **Deduplication**: Prevents alert fatigue with intelligent deduplication

### 🎨 **Enhanced Email Notifications**
- **Professional HTML Formatting**: Modern CSS styling with gradients and shadows
- **Severity-Based Styling**: Color-coded alerts (Red/Yellow/Green) with emoji icons
- **Timezone Conversion**: Automatic UTC → IST conversion for local time display
- **Mobile-Responsive Design**: Works on all devices and email clients
- **Multi-Format Support**: HTML + text fallback for compatibility
- **Enhanced Subject Lines**: Visual indicators with severity emojis

## 📁 Project Structure

```
major project/
├── agent/monitor/
│   ├── agent_core.c          # C agent for process hooking & memory dumping
│   └── __init__.py
├── detection/
│   ├── yara_scanner.py       # Enhanced memory scanner with cross-platform support
│   ├── disassembler.py       # Capstone-based disassembler with pattern detection
│   ├── orchestrator.py       # Central coordination with SIEM & reporting
│   ├── disk_scanner.py       # File-based YARA scanning
│   └── __init__.py
├── config/
│   ├── agent_config.yaml     # Configuration with SIEM & reporting settings
│   └── yara_rules/
│       └── sample_shellcode.yar
├── utils/
│   ├── email_notifier.py     # SMTP alerting system
│   └── __init__.py
├── docker/
│   └── Dockerfile            # Docker containerization for auto mode
├── test/                     # Test suite
├── logs/                     # Detection logs
├── reports/                  # PDF reports (auto-generated)
├── build/                    # Compiled C agent libraries
├── build_agent.py           # Cross-platform build script
├── install_service.py       # Windows service installation
├── install_service_linux.py # Linux systemd service installation
├── requirements.txt          # Python dependencies
└── README.md
```

## 🛠️ Installation & Setup

### Option 1: Docker Deployment (Recommended)

#### Using Docker Compose (Easiest)
```bash
# Start in auto mode (continuous monitoring)
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down

# Run single scan
docker-compose run --rm detection-engine python detection/orchestrator.py --single-scan
```

#### Using Docker Directly
```bash
# Build Docker image
docker build -t detection-engine -f docker/Dockerfile .

# Run in auto mode (continuous monitoring)
docker run -d \
  --name detection-engine \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/config:/app/config \
  -v /quarantine:/quarantine \
  --cap-add=SYS_PTRACE \
  detection-engine

# View logs
docker logs -f detection-engine

# Run single scan
docker run --rm \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/config:/app/config \
  detection-engine python detection/orchestrator.py --single-scan
```

### Option 2: Local Installation

### 1. Prerequisites
```bash
# Python 3.8+ required
python --version

# C compiler (for agent core)
# Windows: Visual Studio Build Tools
# Linux: gcc
# macOS: Xcode Command Line Tools
```

### 2. Install Dependencies
```bash
# Install Python dependencies (Windows)
py -m pip install -r requirements.txt

# Or generic Python
python -m pip install -r requirements.txt

# Install additional dependencies for PDF reporting
pip install reportlab
```

### 3. Build C Agent Core
```bash
# Build for your platform
py build_agent.py   # Windows
python build_agent.py  # Generic

# Or manually:
# Windows: cl /LD /Fe:agent_core.dll agent/monitor/agent_core.c
# Linux: gcc -shared -fPIC -o libagentcore.so agent/monitor/agent_core.c
# macOS: clang -shared -fPIC -o libagentcore.dylib agent/monitor/agent_core.c
```

### 4. Configure Settings
Copy `config/agent_config.example.yaml` to `config/agent_config.yaml` and edit your values:
```yaml
# Enable features
cloud_storage:
  enabled: true
  primary_provider: "aws"

siem:
  enabled: true
  elasticsearch_url: "http://localhost:9200"

reporting:
  enabled: true
  report_dir: "../reports"
```

## 🚀 Quick Start

### Basic Usage
```bash
# Run single scan (Windows)
py detection/orchestrator.py --single-scan

# Run with PDF report generation
py detection/orchestrator.py --single-scan --generate-report

# Run continuous monitoring
py detection/orchestrator.py

# Generic Python
python detection/orchestrator.py --single-scan
```

### Service Installation
```bash
# Windows (Run as Administrator)
python install_service.py

# Linux (Run as root)
sudo python install_service_linux.py

# Or create startup scripts only
python install_service.py startup
```

### Individual Components
```bash
# YARA memory scanning
py detection/yara_scanner.py <pid> config/yara_rules/sample_shellcode.yar

# Disassembler analysis
py detection/disassembler.py

# Disk scanning
py detection/disk_scanner.py
```

## 🔧 Configuration

### Docker Setup
```bash
# Build and run with Docker
docker build -t detection-engine -f docker/Dockerfile .
docker run -d --name detection-engine detection-engine

# Mount volumes for persistent storage
docker run -d \
  -v ./logs:/app/logs \
  -v ./reports:/app/reports \
  -v ./config:/app/config \
  detection-engine
```

### SIEM Integration
```yaml
siem:
  enabled: true
  elasticsearch_url: "http://your-elasticsearch:9200"
  splunk:
    enabled: true
    hec_url: "https://your-splunk:8088/services/collector"
    hec_token: "YOUR_SPLUNK_HEC_TOKEN"
```

### Email Alerts
```yaml
email:
  smtp_server: smtp.gmail.com
  smtp_port: 587
  smtp_user: your-email@gmail.com
  smtp_password: your-app-password
  recipients:
    - admin@company.com
```

**🎨 Enhanced Email Features:**
- Professional HTML formatting with severity-based styling
- Automatic timezone conversion (UTC → IST)
- Mobile-responsive design for all devices
- Color-coded alerts with emoji indicators
- Multi-format support (HTML + text fallback)

## 📊 Detection Capabilities

### YARA Rules
- Metasploit shellcode patterns
- NOP sled detection
- XOR decryption loops
- Stack pivot techniques
- Syscall chains

### Pattern Detection
- Call-pop address resolution
- XOR decryption loops
- Stack pivot operations
- Multiple syscall sequences
- NOP sleds
- Jump chain obfuscation

### Memory Analysis
- Cross-platform memory reading
- Architecture detection (x86, x64, ARM)
- Suspicious region identification
- Real-time process monitoring

## 🔍 Monitoring & Alerts

### Real-time Monitoring
- Process memory scanning every 5 seconds (configurable)
- Automatic malicious process termination
- Memory dump quarantine
- Deduplication to prevent alert fatigue

### Alert Channels
- Email notifications with detailed event information
- Docker containerized logging for long-term retention
- SIEM integration for centralized monitoring
- PDF reports for compliance and analysis

## 🧪 Testing

### Test Suite
```bash
# Run all tests (quiet)
py -m pytest -q

# Test individual components
py test/test_orchestrator.py
py test/test_email.py

# Test Docker deployment
docker build -t detection-engine -f docker/Dockerfile .
docker run --rm detection-engine python detection/orchestrator.py --single-scan
```

### Sample Malware Testing
```bash
# Create test file
echo "THIS_IS_A_TEST_MALWARE_FILE" > test_malware.txt

# Run detection
python detection/orchestrator.py --single-scan
```

## 🔒 Security Considerations

### Permissions Required
- **Windows**: Administrator privileges for process memory access
- **Linux**: Root privileges or CAP_SYS_PTRACE capability
- **macOS**: Root privileges for process monitoring

### Data Privacy
- Memory dumps contain sensitive process data
- Docker volumes provide secure, isolated storage
- Implement proper access controls for logs and reports
- Use Docker secrets for sensitive configuration

### Performance Impact
- Memory scanning can impact system performance
- Adjust scan intervals based on system resources
- Monitor CPU and memory usage during operation

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:
1. Check the logs in `logs/detections.jsonl`
2. Review configuration in `config/agent_config.yaml`
3. Run tests to verify installation
4. Create an issue with detailed error information

## 🔄 Version History

- **v3.0**: Docker containerization for auto mode deployment, removed cloud storage dependencies
- **v2.1**: Stability improvements to disk scanning, YARA rules refined, Windows-friendly commands
- **v2.0**: Enhanced with SIEM integration, PDF reporting, and cross-platform memory scanning
- **v1.0**: Initial release with basic YARA scanning 

## ℹ️ Notes

- Docker containerization provides isolated, reproducible deployment in auto mode
- Startup scripts available: `start_detection.ps1` (PowerShell) and `start_detection.bat` (CMD) launch the orchestrator using your installed Python
- For Docker deployment, ensure proper volume mounts for logs, reports, and config files