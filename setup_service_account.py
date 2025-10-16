#!/usr/bin/env python3
"""
Service Account Setup for Google Drive
Bypasses OAuth verification issues
"""

import os
import json
from google.oauth2 import service_account
from googleapiclient.discovery import build

def create_service_account_credentials():
    """Create service account credentials"""
    print("🔐 Setting up Service Account for Google Drive")
    print("=" * 50)
    
    # Service account credentials template
    service_account_info = {
        "type": "service_account",
        "project_id": "memory-shellcode-detection",
        "private_key_id": "YOUR_PRIVATE_KEY_ID",
        "private_key": "-----BEGIN PRIVATE KEY-----\nYOUR_PRIVATE_KEY\n-----END PRIVATE KEY-----\n",
        "client_email": "memory-detection@memory-shellcode-detection.iam.gserviceaccount.com",
        "client_id": "YOUR_CLIENT_ID",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/memory-detection%40memory-shellcode-detection.iam.gserviceaccount.com"
    }
    
    # Save service account file
    with open('service-account-key.json', 'w') as f:
        json.dump(service_account_info, f, indent=2)
    
    print("📄 Created service-account-key.json template")
    print("⚠️  You need to replace with real service account credentials")
    
    return service_account_info

def setup_service_account_in_console():
    """Instructions for setting up service account in Google Cloud Console"""
    print("\n📋 Service Account Setup Instructions:")
    print("=" * 40)
    
    print("1. 🌐 Go to Google Cloud Console:")
    print("   https://console.cloud.google.com/")
    
    print("\n2. 🔑 Sign in with your account:")
    print("   Email: ram144973@gmail.com")
    
    print("\n3. 📁 Select your project:")
    print("   Project: memory-shellcode-detection")
    
    print("\n4. 🔧 Go to IAM & Admin:")
    print("   - Navigate to 'IAM & Admin' → 'Service Accounts'")
    print("   - Click 'Create Service Account'")
    print("   - Name: 'memory-detection-sa'")
    print("   - Description: 'Service account for memory detection'")
    print("   - Click 'Create and Continue'")
    
    print("\n5. 🔐 Grant permissions:")
    print("   - Role: 'Editor' (or 'Drive File Stream' for Drive only)")
    print("   - Click 'Continue'")
    print("   - Click 'Done'")
    
    print("\n6. 🔑 Create key:")
    print("   - Click on the service account")
    print("   - Go to 'Keys' tab")
    print("   - Click 'Add Key' → 'Create new key'")
    print("   - Key type: 'JSON'")
    print("   - Click 'Create'")
    print("   - Download the JSON file")
    
    print("\n7. 📥 Place the file:")
    print("   - Rename to 'service-account-key.json'")
    print("   - Place in your project directory")
    
    print("\n8. ✅ Test the setup:")
    print("   python test_service_account.py")

def test_service_account():
    """Test service account access"""
    service_account_file = 'service-account-key.json'
    
    if not os.path.exists(service_account_file):
        print("❌ service-account-key.json not found")
        return False
    
    try:
        # Load service account credentials
        credentials = service_account.Credentials.from_service_account_file(
            service_account_file,
            scopes=['https://www.googleapis.com/auth/drive.file']
        )
        
        # Build service
        service = build('drive', 'v3', credentials=credentials)
        
        # Test access
        results = service.files().list(pageSize=1).execute()
        
        print("✅ Service account authentication successful!")
        print("✅ Google Drive access confirmed!")
        return True
        
    except Exception as e:
        print(f"❌ Service account test failed: {e}")
        return False

def main():
    """Main setup function"""
    print("🚀 Service Account Setup for Google Drive")
    print("=" * 60)
    
    # Check if service account file exists
    if os.path.exists('service-account-key.json'):
        print("✅ Found service account file")
        if test_service_account():
            print("\n✅ Setup Complete!")
            print("🚀 You can now run: python detection/orchestrator.py")
        else:
            print("\n❌ Service account test failed")
            setup_service_account_in_console()
    else:
        print("❌ Service account file not found")
        setup_service_account_in_console()

if __name__ == "__main__":
    main()
