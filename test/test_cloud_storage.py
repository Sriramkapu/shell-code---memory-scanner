#!/usr/bin/env python3
"""
Test script for cloud storage functionality
"""

import sys
import os
import json
from datetime import datetime
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.cloud_storage import CloudStorageManager

def test_cloud_storage():
    """Test cloud storage functionality"""
    
    # Sample configuration (you'll need to update with your actual credentials)
    config = {
        'cloud_storage': {
            'enabled': True,
            'primary_provider': 'aws',
            'auto_upload_interval': 300,
            'aws': {
                'access_key_id': 'YOUR_AWS_ACCESS_KEY',
                'secret_access_key': 'YOUR_AWS_SECRET_KEY',
                'region': 'us-east-1',
                'bucket_name': 'your-detection-logs-bucket'
            }
        }
    }
    
    # Create a sample detection event
    sample_event = {
        "timestamp": datetime.now().isoformat(),
        "host": "test-host",
        "process": "test_process.exe",
        "pid": 1234,
        "yara_match": ["Test_NOP_Sled"],
        "action": "Blocked (test)",
        "memory_region_hash": "0x1234567890abcdef",
        "dump_path": "/test/dump.dump"
    }
    
    try:
        # Initialize cloud storage manager
        print("Initializing cloud storage manager...")
        cloud_manager = CloudStorageManager(config)
        
        # Test uploading a single log entry
        print("Testing single log entry upload...")
        success = cloud_manager.upload_log_entry(sample_event, 'aws')
        
        if success:
            print("✅ Single log entry upload successful!")
        else:
            print("❌ Single log entry upload failed!")
        
        # Test uploading a log file
        print("Testing log file upload...")
        test_log_file = "test_detections.jsonl"
        
        # Create a test log file
        with open(test_log_file, 'w') as f:
            f.write(json.dumps(sample_event) + '\n')
            f.write(json.dumps(sample_event) + '\n')
        
        success = cloud_manager.upload_log_file(test_log_file, 'aws')
        
        if success:
            print("✅ Log file upload successful!")
        else:
            print("❌ Log file upload failed!")
        
        # Cleanup test file
        if os.path.exists(test_log_file):
            os.remove(test_log_file)
            
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        print("\nNote: Make sure you have configured your cloud storage credentials in config/agent_config.yaml")

def test_config_loading():
    """Test loading configuration from file"""
    try:
        config_path = os.path.join(os.path.dirname(__file__), '../config/agent_config.yaml')
        if os.path.exists(config_path):
            print("✅ Configuration file found!")
            
            # Test loading config
            import yaml
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if 'cloud_storage' in config:
                print("✅ Cloud storage configuration found!")
                print(f"   Enabled: {config['cloud_storage'].get('enabled', False)}")
                print(f"   Primary Provider: {config['cloud_storage'].get('primary_provider', 'Not set')}")
            else:
                print("❌ Cloud storage configuration not found in config file")
        else:
            print("❌ Configuration file not found!")
            
    except Exception as e:
        print(f"❌ Error loading configuration: {e}")

if __name__ == "__main__":
    print("=== Cloud Storage Test ===")
    print()
    
    print("1. Testing configuration loading...")
    test_config_loading()
    print()
    
    print("2. Testing cloud storage functionality...")
    test_cloud_storage()
    print()
    
    print("=== Test Complete ===")
    print("\nTo use cloud storage:")
    print("1. Update config/agent_config.yaml with your cloud provider credentials")
    print("2. Install required dependencies: pip install -r requirements.txt")
    print("3. Run the orchestrator: python detection/orchestrator.py") 