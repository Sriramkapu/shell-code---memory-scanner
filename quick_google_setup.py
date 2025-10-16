#!/usr/bin/env python3
"""
Quick Google Drive Setup
Simplified setup for ram144973@gmail.com
"""

import os
import webbrowser
import json
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import pickle

# Google Drive API scopes
SCOPES = ['https://www.googleapis.com/auth/drive.file']

def create_oauth_credentials():
    """Create OAuth credentials for the user"""
    print("🔐 Setting up Google Drive Authentication")
    print("=" * 50)
    
    # Check if we already have credentials
    token_path = 'token.pickle'
    if os.path.exists(token_path):
        print("✅ Found existing credentials")
        with open(token_path, 'rb') as token:
            creds = pickle.load(token)
        
        if creds and creds.valid:
            print("✅ Credentials are valid")
            return creds
        elif creds and creds.expired and creds.refresh_token:
            print("🔄 Refreshing expired credentials...")
            creds.refresh(Request())
            return creds
    
    # Create client secrets file if it doesn't exist
    client_secrets_file = 'client_secrets.json'
    if not os.path.exists(client_secrets_file):
        print("📋 Creating client secrets file...")
        create_client_secrets_file()
    
    # Start OAuth flow
    print("🌐 Starting OAuth authentication...")
    print("📱 A browser window will open for you to sign in")
    print("🔑 Please sign in with: ram144973@gmail.com")
    
    try:
        flow = InstalledAppFlow.from_client_secrets_file(
            client_secrets_file, SCOPES)
        creds = flow.run_local_server(port=0)
        
        # Save credentials
        with open(token_path, 'wb') as token:
            pickle.dump(creds, token)
        
        print("✅ Authentication successful!")
        return creds
        
    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        print("📋 Please check the setup guide in GOOGLE_DRIVE_SETUP.md")
        return None

def create_client_secrets_file():
    """Create a basic client secrets file for development"""
    client_secrets = {
        "installed": {
            "client_id": "YOUR_CLIENT_ID.apps.googleusercontent.com",
            "project_id": "memory-shellcode-detection",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": "YOUR_CLIENT_SECRET",
            "redirect_uris": ["http://localhost"]
        }
    }
    
    with open('client_secrets.json', 'w') as f:
        json.dump(client_secrets, f, indent=2)
    
    print("📄 Created client_secrets.json template")
    print("⚠️  You need to replace with real credentials from Google Cloud Console")

def test_google_drive_access(creds):
    """Test if we can access Google Drive"""
    if not creds:
        return False
    
    try:
        service = build('drive', 'v3', credentials=creds)
        
        # Test by listing files
        results = service.files().list(
            pageSize=1,
            fields="files(id, name)"
        ).execute()
        
        print("✅ Successfully connected to Google Drive")
        return True
        
    except Exception as e:
        print(f"❌ Failed to access Google Drive: {e}")
        return False

def setup_detection_folders(creds):
    """Create the necessary folders in Google Drive"""
    if not creds:
        return False
    
    try:
        service = build('drive', 'v3', credentials=creds)
        
        # Create main folder
        main_folder_name = "Memory Shellcode Detection"
        main_folder_id = create_folder_if_not_exists(service, main_folder_name)
        
        if main_folder_id:
            print(f"✅ Created main folder: {main_folder_name}")
            
            # Create subfolders
            subfolders = ['logs', 'memory_dumps', 'reports']
            for subfolder in subfolders:
                subfolder_id = create_folder_if_not_exists(service, subfolder, main_folder_id)
                if subfolder_id:
                    print(f"✅ Created subfolder: {subfolder}")
                else:
                    print(f"❌ Failed to create subfolder: {subfolder}")
            
            return True
        else:
            print("❌ Failed to create main folder")
            return False
            
    except Exception as e:
        print(f"❌ Error creating folders: {e}")
        return False

def create_folder_if_not_exists(service, folder_name, parent_id=None):
    """Create folder if it doesn't exist"""
    try:
        # Search for existing folder
        query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder'"
        if parent_id:
            query += f" and '{parent_id}' in parents"
        
        results = service.files().list(
            q=query,
            spaces='drive',
            fields='files(id, name)'
        ).execute()
        
        files = results.get('files', [])
        
        if files:
            return files[0]['id']
        else:
            # Create new folder
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            
            if parent_id:
                folder_metadata['parents'] = [parent_id]
            
            folder = service.files().create(
                body=folder_metadata,
                fields='id'
            ).execute()
            
            return folder.get('id')
            
    except Exception as e:
        print(f"Error creating folder {folder_name}: {e}")
        return None

def main():
    """Main setup function"""
    print("🚀 Quick Google Drive Setup for ram144973@gmail.com")
    print("=" * 60)
    
    # Step 1: Create OAuth credentials
    creds = create_oauth_credentials()
    
    if creds:
        # Step 2: Test access
        if test_google_drive_access(creds):
            # Step 3: Create folders
            if setup_detection_folders(creds):
                print("\n✅ Setup Complete!")
                print("\n📋 Your detection system is ready!")
                print("📁 Check Google Drive for 'Memory Shellcode Detection' folder")
                print("🚀 Run: python detection/orchestrator.py --single-scan")
            else:
                print("❌ Failed to create folders")
        else:
            print("❌ Failed to access Google Drive")
    else:
        print("❌ Authentication failed")
        print("\n📋 Manual Setup Required:")
        print("1. Go to: https://console.cloud.google.com/")
        print("2. Sign in with: ram144973@gmail.com")
        print("3. Create project: 'Memory Shellcode Detection'")
        print("4. Enable Google Drive API")
        print("5. Create OAuth 2.0 credentials")
        print("6. Download client_secrets.json")
        print("7. Place it in this directory")
        print("8. Run this script again")

if __name__ == "__main__":
    main()
