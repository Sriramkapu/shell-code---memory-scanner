#!/usr/bin/env python3
"""
Google Drive Setup Script
Helps set up Google Drive authentication for the detection system
"""

import os
import json
import pickle
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# Google Drive API scopes
SCOPES = ['https://www.googleapis.com/auth/drive.file']

def setup_google_drive():
    """Set up Google Drive authentication"""
    print("🔐 Google Drive Setup")
    print("=" * 50)
    
    creds = None
    token_path = 'token.pickle'
    
    # Check if token file exists
    if os.path.exists(token_path):
        print("📄 Found existing token file")
        with open(token_path, 'rb') as token:
            creds = pickle.load(token)
    
    # If no valid credentials, get new ones
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            print("🔄 Refreshing expired token...")
            creds.refresh(Request())
        else:
            print("🔑 Getting new credentials...")
            
            # Check for client secrets file
            client_secrets_file = 'client_secrets.json'
            if os.path.exists(client_secrets_file):
                print("📋 Using client secrets file...")
                flow = InstalledAppFlow.from_client_secrets_file(
                    client_secrets_file, SCOPES)
                creds = flow.run_local_server(port=0)
            else:
                print("⚠️  No client secrets file found.")
                print("📝 Creating manual setup...")
                creds = create_manual_credentials()
        
        # Save credentials
        with open(token_path, 'wb') as token:
            pickle.dump(creds, token)
        print("💾 Credentials saved to token.pickle")
    
    # Test the credentials
    if test_credentials(creds):
        print("✅ Google Drive authentication successful!")
        return True
    else:
        print("❌ Google Drive authentication failed!")
        return False

def create_manual_credentials():
    """Create credentials manually for development"""
    print("\n📋 Manual Setup Instructions:")
    print("1. Go to Google Cloud Console: https://console.cloud.google.com/")
    print("2. Create a new project or select existing")
    print("3. Enable Google Drive API")
    print("4. Create OAuth 2.0 credentials")
    print("5. Download client_secrets.json")
    print("6. Place it in this directory")
    print("\nFor now, using default credentials...")
    
    try:
        from google.auth import default
        creds, project = default(scopes=SCOPES)
        return creds
    except Exception as e:
        print(f"❌ Could not create default credentials: {e}")
        return None

def test_credentials(creds):
    """Test if credentials work"""
    try:
        service = build('drive', 'v3', credentials=creds)
        
        # Try to list files (just to test access)
        results = service.files().list(
            pageSize=1,
            fields="files(id, name)"
        ).execute()
        
        print("🔍 Successfully connected to Google Drive")
        return True
        
    except Exception as e:
        print(f"❌ Failed to test credentials: {e}")
        return False

def create_detection_folders():
    """Create necessary folders in Google Drive"""
    print("\n📁 Creating Detection Folders...")
    
    try:
        creds = None
        token_path = 'token.pickle'
        
        if os.path.exists(token_path):
            with open(token_path, 'rb') as token:
                creds = pickle.load(token)
        
        if not creds:
            print("❌ No credentials found. Run setup first.")
            return False
        
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

def list_detection_files():
    """List files in detection folders"""
    print("\n📋 Listing Detection Files...")
    
    try:
        creds = None
        token_path = 'token.pickle'
        
        if os.path.exists(token_path):
            with open(token_path, 'rb') as token:
                creds = pickle.load(token)
        
        if not creds:
            print("❌ No credentials found.")
            return
        
        service = build('drive', 'v3', credentials=creds)
        
        # Find main folder
        main_folder_name = "Memory Shellcode Detection"
        results = service.files().list(
            q=f"name='{main_folder_name}' and mimeType='application/vnd.google-apps.folder'",
            spaces='drive',
            fields='files(id, name)'
        ).execute()
        
        files = results.get('files', [])
        if not files:
            print("❌ Main detection folder not found.")
            return
        
        main_folder_id = files[0]['id']
        
        # List files in each subfolder
        subfolders = ['logs', 'memory_dumps', 'reports']
        for subfolder in subfolders:
            print(f"\n📁 {subfolder.upper()} FOLDER:")
            results = service.files().list(
                q=f"'{main_folder_id}' in parents and name='{subfolder}' and mimeType='application/vnd.google-apps.folder'",
                spaces='drive',
                fields='files(id, name)'
            ).execute()
            
            subfolder_files = results.get('files', [])
            if subfolder_files:
                subfolder_id = subfolder_files[0]['id']
                
                # List files in this subfolder
                file_results = service.files().list(
                    q=f"'{subfolder_id}' in parents",
                    spaces='drive',
                    fields='files(id, name, createdTime, size)'
                ).execute()
                
                files_in_folder = file_results.get('files', [])
                if files_in_folder:
                    for file in files_in_folder:
                        size = file.get('size', 'Unknown')
                        created = file.get('createdTime', 'Unknown')[:19]  # Truncate timestamp
                        print(f"  📄 {file['name']} ({size} bytes) - {created}")
                else:
                    print("  (empty)")
            else:
                print("  (folder not found)")
                
    except Exception as e:
        print(f"❌ Error listing files: {e}")

def main():
    """Main setup function"""
    print("🚀 Memory Shellcode Detection - Google Drive Setup")
    print("=" * 60)
    
    # Step 1: Setup authentication
    if setup_google_drive():
        # Step 2: Create folders
        if create_detection_folders():
            # Step 3: List existing files
            list_detection_files()
            
            print("\n✅ Setup Complete!")
            print("\n📋 Next Steps:")
            print("1. Run the detection system: python detection/orchestrator.py")
            print("2. Check Google Drive for uploaded files")
            print("3. Monitor logs/detections.jsonl for local events")
        else:
            print("❌ Failed to create folders")
    else:
        print("❌ Authentication failed")

if __name__ == "__main__":
    main()
