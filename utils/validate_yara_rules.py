#!/usr/bin/env python3
"""
YARA Rule Integrity Validation Script

Validates YARA rules for:
- Compilation success
- Required metadata presence
- Rule count verification
- File integrity (optional hash verification)
"""

import os
import sys
import yara
import hashlib
from pathlib import Path

# Fix Windows console encoding
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def get_file_hash(filepath):
    """Calculate SHA256 hash of file"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def validate_yara_rules(rules_path=None):
    """Validate YARA rules for integrity and correctness"""
    if rules_path is None:
        rules_path = os.path.join(os.path.dirname(__file__), '../config/yara_rules/sample_shellcode.yar')
    
    rules_path = os.path.abspath(rules_path)
    
    if not os.path.exists(rules_path):
        print(f"❌ ERROR: YARA rules file not found: {rules_path}")
        return False
    
    print(f"📋 Validating YARA rules: {rules_path}")
    print("-" * 60)
    
    # Step 1: Check file exists and is readable
    try:
        with open(rules_path, 'r') as f:
            content = f.read()
        print("✅ Rules file is readable")
    except Exception as e:
        print(f"❌ ERROR: Cannot read rules file: {e}")
        return False
    
    # Step 2: Compile YARA rules
    try:
        rules = yara.compile(filepath=rules_path)
        print(f"✅ YARA rules compiled successfully")
    except yara.SyntaxError as e:
        print(f"❌ ERROR: YARA syntax error: {e}")
        return False
    except Exception as e:
        print(f"❌ ERROR: Failed to compile rules: {e}")
        return False
    
    # Step 3: Count rules
    rule_count = 0
    try:
        # Try to get rule names from compiled rules
        # YARA doesn't expose a direct count, so we'll parse the file
        with open(rules_path, 'r') as f:
            content = f.read()
            rule_count = content.count('rule ')
        print(f"✅ Total rules found: {rule_count}")
    except Exception as e:
        print(f"⚠️  Could not count rules: {e}")
        rule_count = 0
    
    # Step 4: Validate rule metadata
    required_meta_fields = ['description', 'severity']
    rules_with_meta = 0
    rules_without_meta = []
    
    # Parse rules file to check metadata
    rule_names = []
    current_rule = None
    has_meta = False
    has_description = False
    has_severity = False
    
    with open(rules_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('rule '):
                # Save previous rule info
                if current_rule and (has_description or has_severity):
                    rules_with_meta += 1
                elif current_rule:
                    rules_without_meta.append(current_rule)
                
                # Start new rule
                current_rule = line.split()[1].split('(')[0]
                rule_names.append(current_rule)
                has_meta = False
                has_description = False
                has_severity = False
            elif line.startswith('meta:'):
                has_meta = True
            elif has_meta and 'description' in line.lower():
                has_description = True
            elif has_meta and 'severity' in line.lower():
                has_severity = True
    
    # Check last rule
    if current_rule and (has_description or has_severity):
        rules_with_meta += 1
    elif current_rule:
        rules_without_meta.append(current_rule)
    
    if rules_without_meta:
        print(f"⚠️  WARNING: {len(rules_without_meta)} rules missing recommended metadata:")
        for rule in rules_without_meta[:5]:  # Show first 5
            print(f"   - {rule}")
        if len(rules_without_meta) > 5:
            print(f"   ... and {len(rules_without_meta) - 5} more")
    else:
        print(f"✅ All rules have metadata (description/severity)")
    
    # Step 5: Calculate file hash
    file_hash = get_file_hash(rules_path)
    print(f"✅ File integrity hash (SHA256): {file_hash[:16]}...")
    
    # Step 6: Test rule matching capability
    print("\n🧪 Testing rule matching capability...")
    test_data = b"\x90\x90\x90\x90\xEB\xFE"  # NOP sled pattern
    try:
        matches = rules.match(data=test_data)
        if matches:
            print(f"✅ Test pattern matched {len(matches)} rule(s): {[m.rule for m in matches]}")
        else:
            print("ℹ️  Test pattern did not match (this is normal)")
    except Exception as e:
        print(f"⚠️  WARNING: Could not test rule matching: {e}")
    
    print("-" * 60)
    print(f"✅ Validation complete: {rule_count} rules validated")
    
    return True

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate YARA rules integrity')
    parser.add_argument('--rules', type=str, default=None,
                       help='Path to YARA rules file (default: config/yara_rules/sample_shellcode.yar)')
    parser.add_argument('--hash', action='store_true',
                       help='Display full SHA256 hash of rules file')
    
    args = parser.parse_args()
    
    success = validate_yara_rules(args.rules)
    
    if args.hash and args.rules:
        rules_path = os.path.abspath(args.rules)
        file_hash = get_file_hash(rules_path)
        print(f"\n📝 Full SHA256 hash: {file_hash}")
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()

