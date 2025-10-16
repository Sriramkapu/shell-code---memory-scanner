# Google Drive Setup Guide

## 🚀 **Quick Setup for ram144973@gmail.com**

### **Step 1: Create Google Cloud Project**

1. **Go to Google Cloud Console**: https://console.cloud.google.com/
2. **Sign in** with your account: `ram144973@gmail.com`
3. **Create a new project** or select existing:
   - Click "Select a project" → "New Project"
   - Name: `Memory Shellcode Detection`
   - Click "Create"

### **Step 2: Enable Google Drive API**

1. **Go to APIs & Services**: https://console.cloud.google.com/apis
2. **Click "Enable APIs and Services"**
3. **Search for "Google Drive API"**
4. **Click "Enable"**

### **Step 3: Create OAuth 2.0 Credentials**

1. **Go to Credentials**: https://console.cloud.google.com/apis/credentials
2. **Click "Create Credentials"** → "OAuth 2.0 Client IDs"
3. **Application type**: "Desktop application"
4. **Name**: "Memory Detection App"
5. **Click "Create"**
6. **Download the JSON file** (rename to `client_secrets.json`)

### **Step 4: Place Credentials File**

1. **Save `client_secrets.json`** in your project root directory
2. **File structure should be**:
   ```
   major project/
   ├── client_secrets.json  ← Place here
   ├── setup_google_drive.py
   ├── detection/
   └── ...
   ```

### **Step 5: Run Setup Script**

```bash
# Activate virtual environment
.venv\Scripts\activate

# Run setup
python setup_google_drive.py
```

### **Step 6: Authenticate**

1. **Browser will open** to Google OAuth page
2. **Sign in** with `ram144973@gmail.com`
3. **Grant permissions** to the app
4. **Return to terminal** - setup should complete

---

## 🔧 **Alternative: Service Account Setup**

If OAuth doesn't work, use a service account:

### **Step 1: Create Service Account**

1. **Go to IAM & Admin**: https://console.cloud.google.com/iam-admin
2. **Click "Service Accounts"**
3. **Click "Create Service Account"**
4. **Name**: "memory-detection-sa"
5. **Description**: "Service account for memory detection"
6. **Click "Create and Continue"**

### **Step 2: Grant Permissions**

1. **Role**: "Editor" (or custom role with Drive permissions)
2. **Click "Continue"**
3. **Click "Done"**

### **Step 3: Create Key**

1. **Click on the service account**
2. **Go to "Keys" tab**
3. **Click "Add Key"** → "Create new key"
4. **Key type**: "JSON"
5. **Click "Create"**
6. **Download the JSON file**

### **Step 4: Update Configuration**

Edit `config/agent_config.yaml`:
```yaml
google_drive:
  enabled: true
  folder_name: "Memory Shellcode Detection"
  email: "ram144973@gmail.com"
  service_account_file: "service-account-key.json"  # Path to downloaded key
  auto_upload_interval: 300
```

---

## 📁 **What Gets Uploaded to Google Drive**

### **Folder Structure**:
```
Memory Shellcode Detection/
├── logs/
│   ├── detection_20250901_180101.json
│   ├── detection_20250901_180106.json
│   └── detections_20250901_180101_detections.jsonl
├── memory_dumps/
│   ├── 5452_mem.dump
│   ├── 10068_mem.dump
│   └── ...
└── reports/
    └── detection_report_20250901_180101.pdf
```

### **File Types**:
- **JSON Logs**: Individual detection events
- **JSONL Files**: Batch detection logs
- **Memory Dumps**: Suspicious process memory (binary)
- **PDF Reports**: Analysis reports with charts

---

## 🔍 **How to Access Your Data**

### **Via Google Drive Web**:
1. **Go to**: https://drive.google.com/
2. **Sign in** with `ram144973@gmail.com`
3. **Look for folder**: "Memory Shellcode Detection"
4. **Browse subfolders**: logs, memory_dumps, reports

### **Via Python Script**:
```python
from utils.google_drive_storage import GoogleDriveStorageManager
import yaml

# Load config
with open('config/agent_config.yaml', 'r') as f:
    config = yaml.safe_load(f)

# Initialize manager
drive_manager = GoogleDriveStorageManager(config)

# List files
files = drive_manager.list_files('logs')
for name, created in files:
    print(f"{name} - {created}")

# Download file
drive_manager.download_file('detection_20250901_180101.json', 'logs')
```

### **Via Google Drive API**:
```python
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

# Load credentials
with open('token.pickle', 'rb') as token:
    creds = pickle.load(token)

# Build service
service = build('drive', 'v3', credentials=creds)

# List files
results = service.files().list(
    q="name='Memory Shellcode Detection' and mimeType='application/vnd.google-apps.folder'",
    fields="files(id, name)"
).execute()
```

---

## 🚨 **Troubleshooting**

### **Common Issues**:

1. **"Default credentials not found"**:
   - Follow the OAuth setup steps above
   - Make sure `client_secrets.json` is in the right place

2. **"Permission denied"**:
   - Check that you're signed in with `ram144973@gmail.com`
   - Grant all requested permissions

3. **"API not enabled"**:
   - Go to Google Cloud Console
   - Enable Google Drive API

4. **"Quota exceeded"**:
   - Google Drive has daily upload limits
   - Consider reducing upload frequency

### **Testing Upload**:
```python
# Test script
from utils.google_drive_storage import GoogleDriveStorageManager
import yaml

config = yaml.safe_load(open('config/agent_config.yaml'))
drive_manager = GoogleDriveStorageManager(config)

# Test upload
test_data = {
    "timestamp": "2025-09-01T18:00:00",
    "source": "test",
    "message": "Test upload"
}

success = drive_manager.upload_log_entry(test_data)
print(f"Upload successful: {success}")
```

---

## 📊 **Monitoring Uploads**

### **Check Upload Status**:
```bash
# Monitor log file for upload messages
tail -f logs/detections.jsonl | grep "upload"

# Check Google Drive folder
python -c "
from utils.google_drive_storage import GoogleDriveStorageManager
import yaml
config = yaml.safe_load(open('config/agent_config.yaml'))
drive = GoogleDriveStorageManager(config)
files = drive.list_files('logs')
print(f'Files in logs folder: {len(files)}')
"
```

### **Automatic Upload**:
- **Log files**: Uploaded every 5 minutes
- **Memory dumps**: Uploaded immediately when detected
- **Reports**: Uploaded when generated

---

## ✅ **Success Indicators**

When setup is complete, you should see:
1. ✅ **Authentication successful** message
2. ✅ **Folders created** in Google Drive
3. ✅ **Files uploading** when detections occur
4. ✅ **Access to files** via Google Drive web interface

---

## 🔄 **Next Steps After Setup**

1. **Run detection system**:
   ```bash
   python detection/orchestrator.py --single-scan
   ```

2. **Check Google Drive** for uploaded files

3. **Monitor logs**:
   ```bash
   tail -f logs/detections.jsonl
   ```

4. **Generate reports**:
   ```bash
   python detection/orchestrator.py --generate-report
   ```

---

## 📞 **Support**

If you encounter issues:
1. Check the troubleshooting section above
2. Verify Google Cloud project setup
3. Ensure API is enabled
4. Check credentials file placement
5. Review error messages in terminal output
