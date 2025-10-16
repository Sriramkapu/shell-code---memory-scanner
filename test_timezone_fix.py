#!/usr/bin/env python3
"""
Test script to verify timezone conversion functionality
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from utils.email_notifier import convert_utc_to_local, format_detection_event_for_email
from datetime import datetime, timezone

def test_timezone_conversion():
    """Test timezone conversion functionality"""
    print("🧪 Testing Timezone Conversion")
    print("=" * 50)
    
    # Test with the problematic timestamp from the email
    test_timestamp = "2025-09-01T13:31:14.387339+00:00"
    
    print(f"Original UTC timestamp: {test_timestamp}")
    
    # Convert to local time
    local_time = convert_utc_to_local(test_timestamp)
    print(f"Converted to local time: {local_time}")
    
    # Test with a sample event
    sample_event = {
        "timestamp": test_timestamp,
        "source": "disk",
        "file_path": "C:\\Users\\ram14\\OneDrive\\Desktop\\test_malware.exe.txt",
        "yara_match": ["Test_Malware_File"],
        "severity": "High",
        "action": "Alerted"
    }
    
    print(f"\nOriginal event:")
    print(f"  Timestamp: {sample_event['timestamp']}")
    
    # Format for email
    formatted_event = format_detection_event_for_email(sample_event)
    
    print(f"\nFormatted for email:")
    print(f"  Timestamp: {formatted_event['timestamp']}")
    
    # Test current time
    current_utc = datetime.now(timezone.utc).isoformat()
    current_local = convert_utc_to_local(current_utc)
    
    print(f"\nCurrent time test:")
    print(f"  UTC: {current_utc}")
    print(f"  Local: {current_local}")
    
    print(f"\n✅ Timezone conversion test completed!")

if __name__ == "__main__":
    test_timezone_conversion()
