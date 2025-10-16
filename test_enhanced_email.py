#!/usr/bin/env python3
"""
Test script to demonstrate enhanced email notifications
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from utils.email_notifier import send_detection_email_notification
from datetime import datetime, timezone

def test_enhanced_email_notifications():
    """Test the enhanced email notification features"""
    print("🎨 Testing Enhanced Email Notifications")
    print("=" * 60)
    
    # Test memory detection event
    memory_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "memory",
        "host": "localhost",
        "process": "python.exe",
        "pid": 12345,
        "yara_match": ["Test_NOP_Sled", "Suspicious_Pattern"],
        "severity": "High",
        "action": "Blocked (terminated)",
        "memory_region_hash": "0x1234567890abcdef",
        "dump_path": "/quarantine/12345_mem.dump"
    }
    
    print("📧 Sending Memory Detection Alert...")
    print(f"  Source: {memory_event['source']}")
    print(f"  Severity: {memory_event['severity']}")
    print(f"  YARA Matches: {memory_event['yara_match']}")
    
    try:
        send_detection_email_notification(memory_event)
        print("✅ Memory detection email sent successfully!")
    except Exception as e:
        print(f"❌ Failed to send memory detection email: {e}")
    
    print("\n" + "="*60 + "\n")
    
    # Test disk detection event
    disk_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "disk",
        "file_path": "C:\\Users\\ram14\\OneDrive\\Desktop\\suspicious_file.exe",
        "yara_match": ["Test_Malware_File", "Suspicious_Executable"],
        "severity": "Critical",
        "action": "Alerted"
    }
    
    print("📧 Sending Disk Detection Alert...")
    print(f"  Source: {disk_event['source']}")
    print(f"  Severity: {disk_event['severity']}")
    print(f"  YARA Matches: {disk_event['yara_match']}")
    
    try:
        send_detection_email_notification(disk_event)
        print("✅ Disk detection email sent successfully!")
    except Exception as e:
        print(f"❌ Failed to send disk detection email: {e}")
    
    print("\n" + "="*60)
    print("🎉 Enhanced Email Notification Test Completed!")
    print("\n📋 Features Demonstrated:")
    print("  ✅ Rich HTML formatting with CSS styling")
    print("  ✅ Severity-based color coding")
    print("  ✅ Emoji icons for different severity levels")
    print("  ✅ Professional header and footer")
    print("  ✅ Detailed information cards")
    print("  ✅ YARA pattern highlighting")
    print("  ✅ System information display")
    print("  ✅ Timezone conversion (UTC → IST)")
    print("  ✅ Both HTML and text fallback")
    print("  ✅ Enhanced subject lines with emojis")

if __name__ == "__main__":
    test_enhanced_email_notifications()
