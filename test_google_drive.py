#!/usr/bin/env python3
"""
Simple Google Drive Test
Tests basic Google Drive functionality
"""

import os
import json
import tempfile
from datetime import datetime

def test_google_drive_basic():
    """Test basic Google Drive functionality"""
    print("🔍 Testing Google Drive Integration")
    print("=" * 50)
    
    # Check if dependencies are installed
    try:
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from google.auth.transport.requests import Request
        from googleapiclient.discovery import build
        from googleapiclient.http import MediaFileUpload
        print("✅ Google Drive dependencies installed")
    except ImportError as e:
        print(f"❌ Missing Google Drive dependencies: {e}")
        print("Install with: pip install google-auth google-auth-oauthlib google-api-python-client")
        return False
    
    # Check for credentials file
    client_secrets_file = 'client_secrets.json'
    if os.path.exists(client_secrets_file):
        print(f"✅ Found credentials file: {client_secrets_file}")
    else:
        print(f"❌ Missing credentials file: {client_secrets_file}")
        print("📋 Please follow the setup guide in GOOGLE_DRIVE_SETUP.md")
        return False
    
    # Test configuration
    config_path = 'config/agent_config.yaml'
    if os.path.exists(config_path):
        print(f"✅ Found configuration file: {config_path}")
        
        # Check Google Drive config
        import yaml
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        google_drive_config = config.get('google_drive', {})
        if google_drive_config.get('enabled', False):
            print("✅ Google Drive enabled in configuration")
            print(f"   Folder: {google_drive_config.get('folder_name', 'Unknown')}")
            print(f"   Email: {google_drive_config.get('email', 'Unknown')}")
        else:
            print("❌ Google Drive not enabled in configuration")
            return False
    else:
        print(f"❌ Missing configuration file: {config_path}")
        return False
    
    # Test Google Drive manager import
    try:
        from utils.google_drive_storage import GoogleDriveStorageManager
        print("✅ Google Drive storage manager imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import Google Drive storage manager: {e}")
        return False
    
    # Test manager initialization
    try:
        drive_manager = GoogleDriveStorageManager(config)
        print("✅ Google Drive manager initialized")
        
        # Test basic functionality
        if drive_manager.service:
            print("✅ Google Drive service available")
        else:
            print("❌ Google Drive service not available (needs authentication)")
            print("📋 Please run: python setup_google_drive.py")
            return False
            
    except Exception as e:
        print(f"❌ Failed to initialize Google Drive manager: {e}")
        return False
    
    # Test file operations
    print("\n📁 Testing File Operations:")
    
    # Create test data
    test_data = {
        "timestamp": datetime.now().isoformat(),
        "source": "test",
        "test": True,
        "message": "Google Drive integration test"
    }
    
    # Test log entry upload
    try:
        success = drive_manager.upload_log_entry(test_data)
        if success:
            print("✅ Test log entry uploaded successfully")
        else:
            print("❌ Test log entry upload failed")
            return False
    except Exception as e:
        print(f"❌ Upload test failed: {e}")
        return False
    
    # Test file listing
    try:
        files = drive_manager.list_files('logs')
        print(f"✅ Found {len(files)} files in logs folder")
        for name, created in files[:3]:  # Show first 3
            print(f"   📄 {name} - {created}")
    except Exception as e:
        print(f"❌ File listing failed: {e}")
        return False
    
    print("\n✅ Google Drive integration test completed successfully!")
    return True

def test_upload_simulation():
    """Simulate what would be uploaded"""
    print("\n📊 Upload Simulation:")
    print("=" * 30)
    
    # Check what files would be uploaded
    log_path = 'logs/detections.jsonl'
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            lines = f.readlines()
        print(f"📄 Detection logs: {len(lines)} entries ready for upload")
        
        if lines:
            latest_entry = json.loads(lines[-1])
            print(f"   Latest: {latest_entry.get('timestamp', 'Unknown')}")
            print(f"   Source: {latest_entry.get('source', 'Unknown')}")
            print(f"   YARA Match: {latest_entry.get('yara_match', [])}")
    
    # Check memory dumps
    dump_dir = '/quarantine/'
    if os.path.exists(dump_dir):
        dumps = [f for f in os.listdir(dump_dir) if f.endswith('.dump')]
        print(f"💾 Memory dumps: {len(dumps)} files ready for upload")
        for dump in dumps[:3]:
            print(f"   📄 {dump}")
        if len(dumps) > 3:
            print(f"   ... and {len(dumps) - 3} more")
    
    # Check reports
    report_dir = 'reports/'
    if os.path.exists(report_dir):
        reports = [f for f in os.listdir(report_dir) if f.endswith('.pdf')]
        print(f"📊 PDF reports: {len(reports)} files ready for upload")
        for report in reports[:3]:
            print(f"   📄 {report}")

def main():
    """Main test function"""
    print("🚀 Google Drive Integration Test")
    print("=" * 60)
    
    # Test basic functionality
    if test_google_drive_basic():
        # Test upload simulation
        test_upload_simulation()
        
        print("\n✅ All tests passed!")
        print("\n📋 Next Steps:")
        print("1. Follow GOOGLE_DRIVE_SETUP.md for full authentication")
        print("2. Run: python setup_google_drive.py")
        print("3. Test with: python detection/orchestrator.py --single-scan")
    else:
        print("\n❌ Tests failed!")
        print("📋 Please check the setup guide and try again")

if __name__ == "__main__":
    main()
