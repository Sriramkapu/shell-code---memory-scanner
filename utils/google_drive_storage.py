#!/usr/bin/env python3
"""
Google Drive Storage Manager
Handles file uploads and management for Google Drive
"""

import os
import json
import tempfile
import logging
from datetime import datetime
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from googleapiclient.errors import HttpError
import pickle

class GoogleDriveStorageManager:
    def __init__(self, config):
        """
        Initialize Google Drive storage manager
        
        Args:
            config (dict): Configuration containing Google Drive settings
        """
        self.config = config.get('google_drive', {})
        self.logger = logging.getLogger(__name__)
        
        # Google Drive API scopes
        self.SCOPES = ['https://www.googleapis.com/auth/drive.file']
        
        # Initialize Google Drive service
        self.service = None
        self.folder_id = None
        
        self._initialize_service()
        self._setup_folders()
    
    def _initialize_service(self):
        """Initialize Google Drive API service"""
        try:
            creds = None
            
            # Check for service account first
            service_account_file = self.config.get('service_account_file')
            if service_account_file and os.path.exists(service_account_file):
                self.logger.info("Using service account authentication")
                creds = service_account.Credentials.from_service_account_file(
                    service_account_file, scopes=self.SCOPES)
            else:
                # Fall back to OAuth2
                self.logger.info("Using OAuth2 authentication")
                creds = self._initialize_oauth2()
            
            if creds:
                # Build service
                self.service = build('drive', 'v3', credentials=creds)
                self.logger.info("Google Drive service initialized successfully")
            else:
                self.logger.error("Failed to initialize credentials")
                self.service = None
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Google Drive service: {e}")
            self.service = None
    
    def _initialize_oauth2(self):
        """Initialize OAuth2 credentials"""
        try:
            creds = None
            
            # Check if token file exists
            token_path = self.config.get('token_path', 'token.pickle')
            if os.path.exists(token_path):
                with open(token_path, 'rb') as token:
                    creds = pickle.load(token)
            
            # If no valid credentials, get new ones
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    # Use client secrets file or create credentials
                    client_secrets_file = self.config.get('client_secrets_file')
                    if client_secrets_file and os.path.exists(client_secrets_file):
                        flow = InstalledAppFlow.from_client_secrets_file(
                            client_secrets_file, self.SCOPES)
                        creds = flow.run_local_server(port=0)
                    else:
                        # Create credentials manually (for testing)
                        creds = self._create_test_credentials()
                
                # Save credentials
                with open(token_path, 'wb') as token:
                    pickle.dump(creds, token)
            
            return creds
            
        except Exception as e:
            self.logger.error(f"Failed to initialize OAuth2: {e}")
            return None
    
    def _create_test_credentials(self):
        """Create test credentials for development"""
        # This is a simplified approach for development
        # In production, use proper OAuth2 flow
        try:
            from google.auth import default
            creds, project = default(scopes=self.SCOPES)
            return creds
        except Exception:
            self.logger.warning("Could not create test credentials. Please set up OAuth2 properly.")
            return None
    
    def _setup_folders(self):
        """Create necessary folders in Google Drive"""
        if not self.service:
            return
        
        try:
            # Create main folder
            folder_name = self.config.get('folder_name', 'Memory Shellcode Detection')
            self.folder_id = self._create_folder_if_not_exists(folder_name)
            
            # Create subfolders
            subfolders = ['logs', 'memory_dumps', 'reports']
            for subfolder in subfolders:
                self._create_folder_if_not_exists(subfolder, parent_id=self.folder_id)
            
            self.logger.info(f"Google Drive folders setup complete. Main folder ID: {self.folder_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to setup folders: {e}")
    
    def _create_folder_if_not_exists(self, folder_name, parent_id=None):
        """Create folder if it doesn't exist"""
        try:
            # Search for existing folder
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder'"
            if parent_id:
                query += f" and '{parent_id}' in parents"
            
            results = self.service.files().list(
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
                
                folder = self.service.files().create(
                    body=folder_metadata,
                    fields='id'
                ).execute()
                
                return folder.get('id')
                
        except Exception as e:
            self.logger.error(f"Failed to create folder {folder_name}: {e}")
            return None
    
    def upload_file(self, file_path, folder_name='logs'):
        """
        Upload a file to Google Drive
        
        Args:
            file_path (str): Path to file to upload
            folder_name (str): Target folder name (logs, memory_dumps, reports)
        
        Returns:
            bool: True if upload successful, False otherwise
        """
        if not self.service or not os.path.exists(file_path):
            return False
        
        try:
            # Get folder ID
            folder_id = self._create_folder_if_not_exists(folder_name, parent_id=self.folder_id)
            if not folder_id:
                return False
            
            # Create file metadata
            filename = os.path.basename(file_path)
            file_metadata = {
                'name': filename,
                'parents': [folder_id]
            }
            
            # Create media upload
            media = MediaFileUpload(file_path, resumable=True)
            
            # Upload file
            file = self.service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()
            
            self.logger.info(f"Successfully uploaded {filename} to Google Drive")
            return True
            
        except HttpError as error:
            self.logger.error(f"Google Drive upload failed: {error}")
            return False
        except Exception as e:
            self.logger.error(f"Upload error: {e}")
            return False
    
    def upload_log_entry(self, log_entry):
        """
        Upload a single log entry to Google Drive
        
        Args:
            log_entry (dict): Log entry to upload
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"detection_{timestamp}.json"
            
            # Create temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(log_entry, f, indent=2)
                temp_file = f.name
            
            try:
                # Upload file
                success = self.upload_file(temp_file, 'logs')
                return success
            finally:
                # Cleanup
                os.unlink(temp_file)
                
        except Exception as e:
            self.logger.error(f"Failed to upload log entry: {e}")
            return False
    
    def list_files(self, folder_name='logs'):
        """
        List files in a specific folder
        
        Args:
            folder_name (str): Folder name to list
        
        Returns:
            list: List of file names
        """
        if not self.service:
            return []
        
        try:
            folder_id = self._create_folder_if_not_exists(folder_name, parent_id=self.folder_id)
            if not folder_id:
                return []
            
            results = self.service.files().list(
                q=f"'{folder_id}' in parents",
                spaces='drive',
                fields='files(id, name, createdTime)'
            ).execute()
            
            files = results.get('files', [])
            return [(f['name'], f['createdTime']) for f in files]
            
        except Exception as e:
            self.logger.error(f"Failed to list files: {e}")
            return []
    
    def download_file(self, file_name, folder_name='logs', local_path=None):
        """
        Download a file from Google Drive
        
        Args:
            file_name (str): Name of file to download
            folder_name (str): Folder containing the file
            local_path (str): Local path to save file
        
        Returns:
            bool: True if download successful, False otherwise
        """
        if not self.service:
            return False
        
        try:
            folder_id = self._create_folder_if_not_exists(folder_name, parent_id=self.folder_id)
            if not folder_id:
                return False
            
            # Find file
            results = self.service.files().list(
                q=f"name='{file_name}' and '{folder_id}' in parents",
                spaces='drive',
                fields='files(id, name)'
            ).execute()
            
            files = results.get('files', [])
            if not files:
                return False
            
            file_id = files[0]['id']
            
            # Download file
            if not local_path:
                local_path = file_name
            
            request = self.service.files().get_media(fileId=file_id)
            with open(local_path, 'wb') as f:
                f.write(request.execute())
            
            self.logger.info(f"Successfully downloaded {file_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Download failed: {e}")
            return False
    
    def start_auto_upload(self, log_file_path, interval_seconds=300):
        """
        Start automatic upload of log file at specified intervals
        
        Args:
            log_file_path (str): Path to log file to monitor
            interval_seconds (int): Upload interval in seconds
        """
        import threading
        import time
        
        def auto_upload_worker():
            while True:
                try:
                    if os.path.exists(log_file_path):
                        self.upload_file(log_file_path, 'logs')
                    time.sleep(interval_seconds)
                except Exception as e:
                    self.logger.error(f"Auto upload error: {e}")
                    time.sleep(interval_seconds)
        
        thread = threading.Thread(target=auto_upload_worker, daemon=True)
        thread.start()
        self.logger.info(f"Started auto upload for {log_file_path} every {interval_seconds} seconds")
        return thread

def create_google_drive_manager(config_path):
    """
    Create a Google Drive manager from configuration file
    
    Args:
        config_path (str): Path to configuration file
    
    Returns:
        GoogleDriveStorageManager: Initialized Google Drive manager
    """
    import yaml
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    return GoogleDriveStorageManager(config)
