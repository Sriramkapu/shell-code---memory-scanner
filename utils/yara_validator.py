# yara_validator.py
# YARA rule integrity validation and verification utility
import yara
import os
import hashlib
import json
from pathlib import Path

def calculate_file_hash(file_path):
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def validate_yara_rules(rule_path, expected_hash=None):
    """
    Validate YARA rules file integrity and compilation
    
    Args:
        rule_path: Path to YARA rules file
        expected_hash: Optional SHA256 hash to verify against
        
    Returns:
        dict: Validation results with status, rule count, hash, etc.
    """
    results = {
        'valid': False,
        'file_exists': False,
        'compile_success': False,
        'rule_count': 0,
        'file_hash': None,
        'hash_match': None,
        'rules_list': [],
        'errors': []
    }
    
    # Check if file exists
    if not os.path.exists(rule_path):
        results['errors'].append(f"YARA rules file not found: {rule_path}")
        return results
    
    results['file_exists'] = True
    
    # Calculate file hash
    try:
        file_hash = calculate_file_hash(rule_path)
        results['file_hash'] = file_hash
        
        # Verify hash if provided
        if expected_hash:
            results['hash_match'] = (file_hash.lower() == expected_hash.lower())
            if not results['hash_match']:
                results['errors'].append("File hash mismatch - rules may have been tampered with!")
    except Exception as e:
        results['errors'].append(f"Failed to calculate file hash: {e}")
    
    # Try to compile rules
    try:
        rules = yara.compile(filepath=rule_path)
        results['compile_success'] = True
        
        # Get rule information
        try:
            # Try to get rule names from compiled rules
            # YARA-python API varies by version
            if hasattr(rules, 'namespaces'):
                # Older API
                for rule_name in rules.namespaces.get('default', []):
                    rule_info[rule_name] = {
                        'name': rule_name,
                        'tags': getattr(rules[rule_name], 'tags', []),
                        'meta': getattr(rules[rule_name], 'meta', {})
                    }
                    results['rules_list'].append(rule_name)
            else:
                # Newer API - iterate through matches with test data
                test_data = b'\x90\x90\x90\x90'  # Small test data
                try:
                    matches = rules.match(data=test_data)
                    # Get all rule names from the rules object
                    # Try to access rules directly
                    if hasattr(rules, '__iter__'):
                        for rule in rules:
                            rule_name = getattr(rule, 'identifier', str(rule))
                            if rule_name not in results['rules_list']:
                                results['rules_list'].append(rule_name)
                except:
                    # Fallback: try to compile and match with empty data to get rule names
                    pass
                
                # If still no rules found, try to get from string representation
                if not results['rules_list']:
                    # Get rule count from compilation success
                    # We know rules compiled successfully, so count is non-zero
                    # Parse rule file to get rule names
                    try:
                        with open(rule_path, 'r') as f:
                            content = f.read()
                            import re
                            rule_matches = re.findall(r'rule\s+(\w+)', content)
                            results['rules_list'] = list(set(rule_matches))
                    except:
                        pass
        except Exception as e:
            # If we can't enumerate rules, that's okay - compilation succeeded
            pass
        
        results['rule_count'] = len(results['rules_list'])
        results['valid'] = True
        
    except yara.SyntaxError as e:
        results['errors'].append(f"YARA syntax error: {str(e)}")
    except yara.Error as e:
        results['errors'].append(f"YARA compilation error: {str(e)}")
    except Exception as e:
        results['errors'].append(f"Unexpected error compiling rules: {str(e)}")
    
    return results

def verify_rules_integrity(rule_path, signature_file=None):
    """
    Verify YARA rules integrity using signature file
    
    Args:
        rule_path: Path to YARA rules file
        signature_file: Optional path to JSON signature file
        
    Returns:
        dict: Verification results
    """
    # If signature file provided, load expected hash
    expected_hash = None
    if signature_file and os.path.exists(signature_file):
        try:
            with open(signature_file, 'r') as f:
                sig_data = json.load(f)
                expected_hash = sig_data.get('sha256')
        except Exception as e:
            return {
                'verified': False,
                'error': f"Failed to load signature file: {e}"
            }
    
    # Validate rules
    validation = validate_yara_rules(rule_path, expected_hash)
    
    # Determine verification status
    verified = (
        validation['valid'] and 
        validation['compile_success'] and
        (expected_hash is None or validation.get('hash_match', False))
    )
    
    return {
        'verified': verified,
        'validation': validation,
        'message': 'Rules verified successfully' if verified else 'Rules verification failed'
    }

def generate_signature_file(rule_path, output_path):
    """
    Generate signature file for YARA rules
    
    Args:
        rule_path: Path to YARA rules file
        output_path: Path to save signature JSON file
    """
    validation = validate_yara_rules(rule_path)
    
    if not validation['valid']:
        raise ValueError(f"Cannot generate signature for invalid rules: {validation['errors']}")
    
    signature = {
        'file_path': os.path.abspath(rule_path),
        'sha256': validation['file_hash'],
        'rule_count': validation['rule_count'],
        'rules': validation['rules_list'],
        'generated_at': str(Path(rule_path).stat().st_mtime)
    }
    
    with open(output_path, 'w') as f:
        json.dump(signature, f, indent=2)
    
    return signature

if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="YARA Rules Integrity Validator")
    parser.add_argument('rules_file', help='Path to YARA rules file')
    parser.add_argument('--signature', '-s', help='Path to signature file for verification')
    parser.add_argument('--generate-signature', '-g', help='Generate signature file at specified path')
    args = parser.parse_args()
    
    rule_path = args.rules_file
    signature_file = args.signature
    
    # Validate rules
    validation = validate_yara_rules(rule_path)
    
    print("=" * 60)
    print("YARA Rules Validation Report")
    print("=" * 60)
    print(f"File: {rule_path}")
    print(f"Exists: {validation['file_exists']}")
    print(f"Compiles: {validation['compile_success']}")
    print(f"Rules Count: {validation['rule_count']}")
    print(f"SHA256 Hash: {validation['file_hash']}")
    
    if validation['hash_match'] is not None:
        print(f"Hash Match: {validation['hash_match']}")
    
    if validation['errors']:
        print("\nErrors:")
        for error in validation['errors']:
            print(f"  - {error}")
    
    if validation['rules_list']:
        print(f"\nRules ({validation['rule_count']}):")
        for rule in validation['rules_list'][:10]:  # Show first 10
            print(f"  - {rule}")
        if len(validation['rules_list']) > 10:
            print(f"  ... and {len(validation['rules_list']) - 10} more")
    
    print("\n" + "=" * 60)
    
    # Generate signature if requested
    if args.generate_signature:
        try:
            signature = generate_signature_file(rule_path, args.generate_signature)
            print(f"\n[OK] Signature file generated: {args.generate_signature}")
            print(f"  SHA256: {signature['sha256']}")
        except Exception as e:
            print(f"\n[ERROR] Failed to generate signature: {e}")
    
    # Verify with signature if provided
    if signature_file:
        verification = verify_rules_integrity(rule_path, signature_file)
        status = 'VERIFIED' if verification['verified'] else 'FAILED'
        print(f"\nVerification Status: [{status}]")
        print(f"Message: {verification['message']}")

