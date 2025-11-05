"""
Enhanced logging utilities with rotating file handlers and log aggregation
"""
import logging
import logging.handlers
import os
import json
from datetime import datetime, timezone
from pathlib import Path


class RotatingJSONLogger:
    """JSON logger with rotating file handler"""
    
    def __init__(self, log_file_path, max_bytes=10*1024*1024, backup_count=5):
        """
        Initialize rotating JSON logger
        
        Args:
            log_file_path: Path to log file
            max_bytes: Maximum size of log file before rotation (default: 10MB)
            backup_count: Number of backup files to keep (default: 5)
        """
        self.log_file_path = log_file_path
        self.log_dir = os.path.dirname(log_file_path)
        
        # Ensure log directory exists
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Set up rotating file handler
        handler = logging.handlers.RotatingFileHandler(
            log_file_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        
        # Set up logger
        self.logger = logging.getLogger('detection_engine')
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(handler)
        
        # Prevent duplicate handlers
        if len(self.logger.handlers) > 1:
            self.logger.handlers.pop(0)
    
    def log_detection(self, event):
        """Log detection event as JSON"""
        try:
            # Ensure event has timestamp
            if 'timestamp' not in event:
                event['timestamp'] = datetime.now(timezone.utc).isoformat()
            
            # Write as JSON line
            with open(self.log_file_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event) + '\n')
            
            # Also log to standard logger
            self.logger.info(f"Detection: {event.get('yara_match', [])} - {event.get('severity', 'Unknown')}")
        except Exception as e:
            self.logger.error(f"Failed to log detection event: {e}")
    
    def log_error(self, message, exc_info=None):
        """Log error message"""
        self.logger.error(message, exc_info=exc_info)
    
    def log_warning(self, message):
        """Log warning message"""
        self.logger.warning(message)
    
    def log_info(self, message):
        """Log info message"""
        self.logger.info(message)


def aggregate_logs(log_file_path, filters=None):
    """
    Aggregate and analyze detection logs
    
    Args:
        log_file_path: Path to JSONL log file
        filters: Optional dict of filters (e.g., {'severity': 'High', 'source': 'memory'})
    
    Returns:
        dict with aggregated statistics
    """
    stats = {
        'total_detections': 0,
        'by_source': {},
        'by_severity': {},
        'by_rule': {},
        'recent_detections': []
    }
    
    if not os.path.exists(log_file_path):
        return stats
    
    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    
                    # Apply filters if provided
                    if filters:
                        match = True
                        for key, value in filters.items():
                            if event.get(key) != value:
                                match = False
                                break
                        if not match:
                            continue
                    
                    stats['total_detections'] += 1
                    
                    # Aggregate by source
                    source = event.get('source', 'unknown')
                    stats['by_source'][source] = stats['by_source'].get(source, 0) + 1
                    
                    # Aggregate by severity
                    severity = event.get('severity', 'Unknown')
                    stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
                    
                    # Aggregate by YARA rule
                    for rule in event.get('yara_match', []):
                        stats['by_rule'][rule] = stats['by_rule'].get(rule, 0) + 1
                    
                    # Collect recent detections (last 10)
                    if len(stats['recent_detections']) < 10:
                        stats['recent_detections'].append({
                            'timestamp': event.get('timestamp'),
                            'source': source,
                            'severity': severity,
                            'yara_match': event.get('yara_match', [])
                        })
                
                except json.JSONDecodeError:
                    continue
    
    except Exception as e:
        print(f"Error aggregating logs: {e}")
    
    return stats

