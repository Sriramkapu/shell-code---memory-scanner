#!/usr/bin/env python3
"""
Google Drive Setup Verification
Helps verify and guide through Google Cloud setup
"""

import os
import json

def check_client_secrets():
    """Check if client_secrets.json exists and is valid"""
    print("🔍 Checking Google Cloud Setup")
    print("=" * 40)
    
    client_secrets_file = 'client_secrets.json'
    
    if not os.path.exists(client_secrets_file):
        print("❌ client_secrets.json not found")
        print("\n📋 You need to create OAuth credentials:")
        print("1. Go to: https://console.cloud.google.com/")
        print("2. Sign in with: ram144973@gmail.com")
        print("3. Create project: 'Memory Shellcode Detection'")
        print("4. Enable Google Drive API")
        print("5. Create OAuth 2.0 credentials")
        print("6. Download client_secrets.json")
        print("7. Place it in this directory")
        return False
    
    try:
        with open(client_secrets_file, 'r') as f:
            secrets = json.load(f)
        
        if 'installed' in secrets:
            client_id = secrets['installed'].get('client_id', '')
            if client_id and 'googleusercontent.com' in client_id:
                print("✅ client_secrets.json found and valid")
                print(f"   Client ID: {client_id[:20]}...")
                return True
            else:
                print("❌ Invalid client_id in client_secrets.json")
                return False
        else:
            print("❌ Invalid format in client_secrets.json")
            return False
            
    except json.JSONDecodeError:
        print("❌ Invalid JSON in client_secrets.json")
        return False
    except Exception as e:
        print(f"❌ Error reading client_secrets.json: {e}")
        return False

def show_setup_instructions():
    """Show detailed setup instructions"""
    print("\n📋 Detailed Setup Instructions:")
    print("=" * 40)
    
    print("1. 🌐 Go to Google Cloud Console:")
    print("   https://console.cloud.google.com/")
    
    print("\n2. 🔑 Sign in with your account:")
    print("   Email: ram144973@gmail.com")
    
    print("\n3. 📁 Create a new project:")
    print("   - Click 'Select a project'")
    print("   - Click 'New Project'")
    print("   - Name: 'Memory Shellcode Detection'")
    print("   - Click 'Create'")
    
    print("\n4. 🔌 Enable Google Drive API:")
    print("   - Go to 'APIs & Services' → 'Library'")
    print("   - Search for 'Google Drive API'")
    print("   - Click 'Enable'")
    
    print("\n5. 🔐 Create OAuth credentials:")
    print("   - Go to 'APIs & Services' → 'Credentials'")
    print("   - Click 'Create Credentials'")
    print("   - Select 'OAuth 2.0 Client IDs'")
    print("   - Application type: 'Desktop application'")
    print("   - Name: 'Memory Detection App'")
    print("   - Click 'Create'")
    
    print("\n6. 📥 Download credentials:")
    print("   - Click 'Download JSON'")
    print("   - Save as 'client_secrets.json'")
    print("   - Place in your project directory")
    
    print("\n7. ✅ Run verification:")
    print("   python verify_google_setup.py")

def test_oauth_flow():
    """Test the OAuth flow if credentials exist"""
    if not check_client_secrets():
        return False
    
    print("\n🚀 Testing OAuth Flow...")
    print("📱 A browser window will open for authentication")
    
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build
        
        SCOPES = ['https://www.googleapis.com/auth/drive.file']
        
        # Start OAuth flow
        flow = InstalledAppFlow.from_client_secrets_file(
            'client_secrets.json', SCOPES)
        creds = flow.run_local_server(port=0)
        
        # Test access
        service = build('drive', 'v3', credentials=creds)
        results = service.files().list(pageSize=1).execute()
        
        print("✅ OAuth authentication successful!")
        print("✅ Google Drive access confirmed!")
        
        # Save credentials for future use
        import pickle
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
        print("💾 Credentials saved to token.pickle")
        
        return True
        
    except Exception as e:
        print(f"❌ OAuth test failed: {e}")
        return False

def main():
    """Main verification function"""
    print("🔍 Google Drive Setup Verification")
    print("=" * 50)
    
    # Check if credentials exist
    if check_client_secrets():
        # Test OAuth flow
        if test_oauth_flow():
            print("\n✅ Setup Complete!")
            print("🚀 You can now run: python detection/orchestrator.py")
        else:
            print("\n❌ OAuth test failed")
            show_setup_instructions()
    else:
        show_setup_instructions()

if __name__ == "__main__":
    main()
