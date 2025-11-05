#!/usr/bin/env python3
"""
Complete system test for Memory Shellcode Detection Framework
Tests all components working together
"""

import os
import sys
import tempfile
import shutil
import json
import time
import subprocess
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def test_yara_scanner():
    """Test YARA scanner functionality"""
    print("Testing YARA scanner...")

    from detection import yara_scanner

    # Test rule loading
    rules = yara_scanner.load_rules('config/yara_rules/sample_shellcode.yar')
    assert rules is not None, "Failed to load YARA rules"
    print("✓ YARA rules loaded successfully")

    # Test memory reading (simulated)
    test_data = b'\x90\x90\x90\x90\xeb\xfe'  # NOP sled + infinite loop
    matches = rules.match(data=test_data)
    assert len(matches) > 0, "Failed to detect test pattern"
    print("✓ YARA pattern detection working")


def test_disassembler():
    """Test disassembler functionality"""
    print("Testing disassembler...")

    from detection import disassembler

    # Test disassembly
    test_code = b'\x55\x48\x8b\x05\xb8\x13\x00\x00\x90\x90\x90\x90\xeb\xfe'
    result = disassembler.analyze_suspicious_region(test_code)

    assert 'signatures' in result, "Missing signatures in result"
    assert 'patterns' in result, "Missing patterns in result"
    print("✓ Disassembler analysis working")


# Cloud storage test removed - using Docker instead


def test_email_notifier():
    """Test email notification functionality"""
    print("Testing email notifier...")

    from utils.email_notifier import send_email_notification

    # Test with mock data (won't actually send)
    subject = "Test Alert"
    body = "This is a test notification"

    # This should not fail even if email is not configured
    send_email_notification(subject, body)
    print("✓ Email notifier working (no actual email sent)")


def test_disk_scanner():
    """Test disk scanner functionality"""
    print("Testing disk scanner...")

    from detection import disk_scanner
    from detection import yara_scanner

    # Create temporary test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("THIS_IS_A_TEST_MALWARE_FILE")
        test_file = f.name

    try:
        # Load rules
        rules = yara_scanner.load_rules('config/yara_rules/sample_shellcode.yar')

        # Scan test file
        results = disk_scanner.scan_files_with_yara([os.path.dirname(test_file)], rules)

        assert any(r.get('file_path') == test_file for r in results), "Failed to detect test malware file"
        print("✓ Disk scanner working")
    finally:
        # Cleanup
        os.unlink(test_file)


def test_orchestrator():
    """Test orchestrator functionality"""
    print("Testing orchestrator...")

    # Test orchestrator import
    from detection import orchestrator

    # Test config loading
    config = orchestrator.load_config()
    assert config is not None, "Failed to load configuration"
    assert 'monitored_processes' in config, "Missing monitored_processes in config"
    print("✓ Orchestrator configuration loading working")


def test_c_agent_build():
    """Test C agent build process"""
    print("Testing C agent build...")

    # Check if build script exists
    build_script = 'build_agent.py'
    assert os.path.exists(build_script), "Build script not found"

    # Check if agent_core.c exists
    agent_core = 'agent/monitor/agent_core.c'
    assert os.path.exists(agent_core), "agent_core.c not found"

    print("✓ C agent source files present")
    # Note: Actual compilation requires proper build environment
    # This test just verifies the source files exist


def test_configuration():
    """Test configuration file"""
    print("Testing configuration...")

    import yaml

    config_path = 'config/agent_config.yaml'
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    # Check required sections (cloud_storage removed - using Docker instead)
    required_sections = ['monitored_processes', 'email', 'siem', 'reporting']
    for section in required_sections:
        assert section in config, f"Missing {section} in configuration"

    print("✓ Configuration file structure valid")


def test_yara_rules():
    """Test YARA rules file"""
    print("Testing YARA rules...")

    rules_path = 'config/yara_rules/sample_shellcode.yar'
    assert os.path.exists(rules_path), "YARA rules file not found"

    # Test rule compilation
    import yara
    rules = yara.compile(filepath=rules_path)
    assert rules is not None, "Failed to compile YARA rules"

    print("✓ YARA rules file valid")


def run_complete_test():
    """Run all tests"""
    print("=" * 60)
    print("Memory Shellcode Detection Framework - Complete System Test")
    print("=" * 60)
    print(f"Test started at: {datetime.now()}")
    print()

    tests = [
        ("Configuration", test_configuration),
        ("YARA Rules", test_yara_rules),
        ("YARA Scanner", test_yara_scanner),
        ("Disassembler", test_disassembler),
        ("Email Notifier", test_email_notifier),
        ("Disk Scanner", test_disk_scanner),
        ("Orchestrator", test_orchestrator),
        ("C Agent Build", test_c_agent_build),
    ]

    results = []
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        try:
            test_func()
            results.append((test_name, True))
        except Exception as e:
            print(f"✗ {test_name} test failed with exception: {e}")
            results.append((test_name, False))

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = 0
    total = len(results)

    for test_name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{test_name:<20} {status}")
        if success:
            passed += 1

    print(f"\nResults: {passed}/{total} tests passed")

    assert passed == total, "Some tests failed"


if __name__ == "__main__":
    run_complete_test()
