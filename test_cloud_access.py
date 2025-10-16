#!/usr/bin/env python3
"""
Test script to verify cloud storage access and show what data would be uploaded
"""

import os
import json
import yaml
from datetime import datetime
from utils.cloud_storage import CloudStorageManager

def test_cloud_storage():
    """Test cloud storage functionality"""
    print("🔍 Testing Cloud Storage Access")
    print("=" * 50)
    
    # Load configuration
    config_path = 'config/agent_config.yaml'
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Initialize cloud storage manager
    cloud_manager = CloudStorageManager(config)
    
    # Check client status
    print("📊 Cloud Client Status:")
    print(f"  AWS Client: {'✅ Connected' if cloud_manager.aws_client else '❌ Not Connected'}")
    print(f"  Azure Client: {'✅ Connected' if cloud_manager.azure_client else '❌ Not Connected'}")
    print(f"  GCP Client: {'✅ Connected' if cloud_manager.gcp_client else '❌ Not Connected'}")
    
    # Check what would be uploaded
    print("\n📁 Files That Would Be Uploaded:")
    
    # Check log file
    log_path = 'logs/detections.jsonl'
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            lines = f.readlines()
        print(f"  📄 Detection Logs: {len(lines)} entries")
        if lines:
            latest_entry = json.loads(lines[-1])
            print(f"     Latest: {latest_entry.get('timestamp', 'Unknown')}")
            print(f"     Source: {latest_entry.get('source', 'Unknown')}")
            print(f"     YARA Match: {latest_entry.get('yara_match', [])}")
    
    # Check memory dumps
    dump_dir = '/quarantine/'
    if os.path.exists(dump_dir):
        dumps = [f for f in os.listdir(dump_dir) if f.endswith('.dump')]
        print(f"  💾 Memory Dumps: {len(dumps)} files")
        for dump in dumps[:3]:  # Show first 3
            print(f"     - {dump}")
        if len(dumps) > 3:
            print(f"     ... and {len(dumps) - 3} more")
    
    # Check reports
    report_dir = 'reports/'
    if os.path.exists(report_dir):
        reports = [f for f in os.listdir(report_dir) if f.endswith('.pdf')]
        print(f"  📊 PDF Reports: {len(reports)} files")
        for report in reports[:3]:
            print(f"     - {report}")
    
    # Test upload functionality
    print("\n🚀 Testing Upload Functionality:")
    
    # Create test data
    test_data = {
        "timestamp": datetime.now().isoformat(),
        "source": "test",
        "test": True,
        "message": "Cloud storage test"
    }
    
    # Test log entry upload
    if cloud_manager.aws_client:
        print("  🔄 Testing AWS S3 upload...")
        try:
            success = cloud_manager.upload_log_entry(test_data, 'aws')
            if success:
                print("  ✅ AWS upload successful!")
            else:
                print("  ❌ AWS upload failed (check credentials)")
        except Exception as e:
            print(f"  ❌ AWS upload error: {e}")
    
    if cloud_manager.azure_client:
        print("  🔄 Testing Azure upload...")
        try:
            success = cloud_manager.upload_log_entry(test_data, 'azure')
            if success:
                print("  ✅ Azure upload successful!")
            else:
                print("  ❌ Azure upload failed (check connection string)")
        except Exception as e:
            print(f"  ❌ Azure upload error: {e}")
    
    if cloud_manager.gcp_client:
        print("  🔄 Testing GCP upload...")
        try:
            success = cloud_manager.upload_log_entry(test_data, 'gcp')
            if success:
                print("  ✅ GCP upload successful!")
            else:
                print("  ❌ GCP upload failed (check credentials)")
        except Exception as e:
            print(f"  ❌ GCP upload error: {e}")
    
    print("\n📋 Next Steps:")
    print("1. Update config/agent_config.yaml with real credentials")
    print("2. Create cloud storage bucket/container")
    print("3. Run this test again to verify access")
    print("4. Start the detection system for real uploads")

if __name__ == "__main__":
    test_cloud_storage()
