import os
import json
import boto3
import azure.storage.blob
from google.cloud import storage
import logging
from datetime import datetime
import threading
import time

class CloudStorageManager:
    def __init__(self, config):
        """
        Initialize cloud storage manager with configuration
        
        Args:
            config (dict): Configuration containing cloud storage settings
        """
        self.config = config
        self.cloud_providers = config.get('cloud_storage', {})
        self.logger = logging.getLogger(__name__)
        
        # Initialize cloud clients
        self.aws_client = None
        self.azure_client = None
        self.gcp_client = None
        
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Initialize cloud provider clients based on configuration"""
        try:
            # AWS S3
            if 'aws' in self.cloud_providers:
                aws_config = self.cloud_providers['aws']
                self.aws_client = boto3.client(
                    's3',
                    aws_access_key_id=aws_config.get('access_key_id'),
                    aws_secret_access_key=aws_config.get('secret_access_key'),
                    region_name=aws_config.get('region', 'us-east-1')
                )
                self.aws_bucket = aws_config.get('bucket_name')
            
            # Azure Blob Storage
            if 'azure' in self.cloud_providers:
                azure_config = self.cloud_providers['azure']
                connection_string = azure_config.get('connection_string')
                if connection_string:
                    self.azure_client = azure.storage.blob.BlobServiceClient.from_connection_string(
                        connection_string
                    )
                    self.azure_container = azure_config.get('container_name')
            
            # Google Cloud Storage
            if 'gcp' in self.cloud_providers:
                gcp_config = self.cloud_providers['gcp']
                credentials_path = gcp_config.get('credentials_path')
                if credentials_path and os.path.exists(credentials_path):
                    self.gcp_client = storage.Client.from_service_account_json(credentials_path)
                    self.gcp_bucket = self.gcp_client.bucket(gcp_config.get('bucket_name'))
                
        except Exception as e:
            self.logger.error(f"Failed to initialize cloud clients: {e}")
    
    def upload_log_file(self, log_file_path, cloud_provider='aws'):
        """
        Upload a log file to the specified cloud provider
        
        Args:
            log_file_path (str): Path to the log file to upload
            cloud_provider (str): Cloud provider ('aws', 'azure', 'gcp')
        
        Returns:
            bool: True if upload successful, False otherwise
        """
        if not os.path.exists(log_file_path):
            self.logger.error(f"Log file not found: {log_file_path}")
            return False
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.basename(log_file_path)
            cloud_filename = f"detections_{timestamp}_{filename}"
            
            if cloud_provider == 'aws' and self.aws_client:
                return self._upload_to_aws(log_file_path, cloud_filename)
            elif cloud_provider == 'azure' and self.azure_client:
                return self._upload_to_azure(log_file_path, cloud_filename)
            elif cloud_provider == 'gcp' and self.gcp_client:
                return self._upload_to_gcp(log_file_path, cloud_filename)
            else:
                self.logger.error(f"Cloud provider {cloud_provider} not configured or not available")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to upload log file: {e}")
            return False
    
    def _upload_to_aws(self, file_path, cloud_filename):
        """Upload file to AWS S3"""
        try:
            self.aws_client.upload_file(
                file_path, 
                self.aws_bucket, 
                f"logs/{cloud_filename}"
            )
            self.logger.info(f"Successfully uploaded {file_path} to AWS S3")
            return True
        except Exception as e:
            self.logger.error(f"AWS upload failed: {e}")
            return False
    
    def _upload_to_azure(self, file_path, cloud_filename):
        """Upload file to Azure Blob Storage"""
        try:
            blob_client = self.azure_client.get_blob_client(
                container=self.azure_container, 
                blob=f"logs/{cloud_filename}"
            )
            with open(file_path, "rb") as data:
                blob_client.upload_blob(data, overwrite=True)
            self.logger.info(f"Successfully uploaded {file_path} to Azure Blob Storage")
            return True
        except Exception as e:
            self.logger.error(f"Azure upload failed: {e}")
            return False
    
    def _upload_to_gcp(self, file_path, cloud_filename):
        """Upload file to Google Cloud Storage"""
        try:
            blob = self.gcp_bucket.blob(f"logs/{cloud_filename}")
            blob.upload_from_filename(file_path)
            self.logger.info(f"Successfully uploaded {file_path} to Google Cloud Storage")
            return True
        except Exception as e:
            self.logger.error(f"GCP upload failed: {e}")
            return False
    
    def upload_log_entry(self, log_entry, cloud_provider='aws'):
        """
        Upload a single log entry to cloud storage
        
        Args:
            log_entry (dict): Log entry to upload
            cloud_provider (str): Cloud provider to use
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"detection_{timestamp}.json"
            
            # Create temporary file with single entry
            temp_file = f"/tmp/{filename}"
            with open(temp_file, 'w') as f:
                json.dump(log_entry, f)
            
            # Upload and cleanup
            success = self.upload_log_file(temp_file, cloud_provider)
            os.remove(temp_file)
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to upload log entry: {e}")
            return False
    
    def start_auto_upload(self, log_file_path, interval_seconds=300, cloud_provider='aws'):
        """
        Start automatic upload of log file at specified intervals
        
        Args:
            log_file_path (str): Path to log file to monitor
            interval_seconds (int): Upload interval in seconds
            cloud_provider (str): Cloud provider to use
        """
        def auto_upload_worker():
            while True:
                try:
                    if os.path.exists(log_file_path):
                        self.upload_log_file(log_file_path, cloud_provider)
                    time.sleep(interval_seconds)
                except Exception as e:
                    self.logger.error(f"Auto upload error: {e}")
                    time.sleep(interval_seconds)
        
        thread = threading.Thread(target=auto_upload_worker, daemon=True)
        thread.start()
        self.logger.info(f"Started auto upload for {log_file_path} every {interval_seconds} seconds")
        return thread

def create_cloud_storage_manager(config_path):
    """
    Create a cloud storage manager from configuration file
    
    Args:
        config_path (str): Path to configuration file
    
    Returns:
        CloudStorageManager: Initialized cloud storage manager
    """
    import yaml
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    return CloudStorageManager(config) 