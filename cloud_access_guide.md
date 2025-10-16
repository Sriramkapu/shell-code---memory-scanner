# Cloud Storage Access Guide

## 🔐 **AWS S3 Access**

### **1. Setup AWS Credentials:**

```bash
# Install AWS CLI
pip install awscli

# Configure AWS credentials
aws configure
# Enter your Access Key ID
# Enter your Secret Access Key
# Enter region (e.g., us-east-1)
```

### **2. Update Configuration:**

Edit `config/agent_config.yaml`:
```yaml
cloud_storage:
  enabled: true
  primary_provider: "aws"
  aws:
    access_key_id: "AKIAIOSFODNN7EXAMPLE"
    secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    region: "us-east-1"
    bucket_name: "my-detection-logs-bucket"
```

### **3. Access Your Data:**

```bash
# List all files in your bucket
aws s3 ls s3://my-detection-logs-bucket/

# Download detection logs
aws s3 cp s3://my-detection-logs-bucket/logs/ ./local-logs/

# View specific log file
aws s3 cp s3://my-detection-logs-bucket/logs/detections_20250901_180101_detections.jsonl -

# Download memory dumps
aws s3 cp s3://my-detection-logs-bucket/memory_dumps/ ./local-dumps/
```

### **4. Web Console Access:**
- Go to: https://console.aws.amazon.com/s3/
- Navigate to your bucket: `my-detection-logs-bucket`
- Browse files in `logs/`, `memory_dumps/`, `reports/` folders

---

## ☁️ **Azure Blob Storage Access**

### **1. Setup Azure CLI:**

```bash
# Install Azure CLI
pip install azure-cli

# Login to Azure
az login
```

### **2. Update Configuration:**

```yaml
cloud_storage:
  enabled: true
  primary_provider: "azure"
  azure:
    connection_string: "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;EndpointSuffix=core.windows.net"
    container_name: "detection-logs"
```

### **3. Access Your Data:**

```bash
# List blobs in container
az storage blob list --container-name detection-logs --account-name myaccount

# Download files
az storage blob download --container-name detection-logs --name logs/detections_20250901_180101.jsonl --file local-file.jsonl

# Download all logs
az storage blob download-batch --source detection-logs --destination ./local-logs/
```

### **4. Web Portal Access:**
- Go to: https://portal.azure.com
- Navigate to Storage Account → Blob Service → Containers
- Browse `detection-logs` container

---

## 🌐 **Google Cloud Storage Access**

### **1. Setup GCP CLI:**

```bash
# Install Google Cloud SDK
pip install google-cloud-sdk

# Authenticate
gcloud auth login
```

### **2. Update Configuration:**

```yaml
cloud_storage:
  enabled: true
  primary_provider: "gcp"
  gcp:
    credentials_path: "path/to/service-account-key.json"
    bucket_name: "my-detection-logs-bucket"
```

### **3. Access Your Data:**

```bash
# List objects in bucket
gsutil ls gs://my-detection-logs-bucket/

# Download files
gsutil cp gs://my-detection-logs-bucket/logs/detections_20250901_180101.jsonl ./

# Download entire logs folder
gsutil -m cp -r gs://my-detection-logs-bucket/logs/ ./local-logs/
```

### **4. Web Console Access:**
- Go to: https://console.cloud.google.com/storage/browser
- Navigate to your bucket: `my-detection-logs-bucket`
- Browse folders and files

---

## 📊 **Data Analysis Examples**

### **1. Analyze Detection Patterns:**

```python
import json
import pandas as pd

# Download and analyze logs
with open('detections_20250901_180101.jsonl', 'r') as f:
    data = [json.loads(line) for line in f]

df = pd.DataFrame(data)
print(f"Total detections: {len(df)}")
print(f"Memory detections: {len(df[df['source'] == 'memory'])}")
print(f"Disk detections: {len(df[df['source'] == 'disk'])}")
```

### **2. Search for Specific Threats:**

```bash
# Search for specific YARA rules
aws s3 cp s3://my-bucket/logs/ - | grep "Metasploit"

# Find high severity alerts
aws s3 cp s3://my-bucket/logs/ - | grep '"severity": "High"'
```

### **3. Download Recent Detections:**

```bash
# Get last 24 hours of logs
aws s3 cp s3://my-bucket/logs/ --recursive --exclude "*" --include "*$(date +%Y%m%d)*"
```

---

## 🔧 **Troubleshooting**

### **Common Issues:**

1. **Access Denied:**
   ```bash
   # Check credentials
   aws sts get-caller-identity
   ```

2. **Bucket Not Found:**
   ```bash
   # List your buckets
   aws s3 ls
   ```

3. **Upload Failures:**
   ```bash
   # Check permissions
   aws s3api get-bucket-policy --bucket my-bucket
   ```

### **Monitoring Uploads:**

```python
# Check upload status in logs
tail -f logs/detections.jsonl | grep "upload"
```

---

## 📈 **Best Practices**

1. **Security:**
   - Use IAM roles instead of access keys
   - Enable bucket encryption
   - Set up access logging

2. **Cost Optimization:**
   - Use lifecycle policies to archive old data
   - Compress files before upload
   - Use appropriate storage classes

3. **Compliance:**
   - Enable versioning for audit trails
   - Set up retention policies
   - Use cross-region replication for backup
