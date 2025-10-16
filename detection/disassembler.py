# disassembler.py
# Capstone-based disassembler wrapper with shellcode pattern detection
from capstone import *
import re

# --- Shellcode pattern detection ---
class ShellcodePatternDetector:
    def __init__(self):
        self.suspicious_patterns = {
            'call_pop': {
                'description': 'Call-Pop technique for getting address',
                'instructions': ['call', 'pop'],
                'pattern': r'call.*\n.*pop'
            },
            'xor_loop': {
                'description': 'XOR decryption loop',
                'instructions': ['xor', 'loop'],
                'pattern': r'xor.*\n.*loop'
            },
            'stack_pivot': {
                'description': 'Stack pivot technique',
                'instructions': ['mov', 'esp'],
                'pattern': r'mov.*esp'
            },
            'syscall_chain': {
                'description': 'Multiple syscalls in sequence',
                'instructions': ['syscall', 'int'],
                'pattern': r'(syscall|int 0x80).*\n.*(syscall|int 0x80)'
            },
            'nop_sled': {
                'description': 'NOP sled for execution flow',
                'instructions': ['nop'],
                'pattern': r'nop.*nop.*nop.*nop'
            },
            'jmp_chain': {
                'description': 'Jump chain for obfuscation',
                'instructions': ['jmp', 'jz', 'jnz'],
                'pattern': r'(jmp|jz|jnz).*\n.*(jmp|jz|jnz)'
            }
        }
    
    def detect_patterns(self, instructions):
        """Detect suspicious shellcode patterns in disassembled code"""
        patterns_found = []
        instruction_text = '\n'.join([f"{ins.mnemonic} {ins.op_str}" for ins in instructions])
        
        for pattern_name, pattern_info in self.suspicious_patterns.items():
            if re.search(pattern_info['pattern'], instruction_text, re.IGNORECASE):
                patterns_found.append({
                    'pattern': pattern_name,
                    'description': pattern_info['description'],
                    'severity': 'High' if pattern_name in ['syscall_chain', 'stack_pivot'] else 'Medium'
                })
        
        return patterns_found

# --- Disassemble memory region with pattern detection ---
def disassemble_bytes(mem_bytes, base_addr=0x1000, arch=CS_ARCH_X86, mode=CS_MODE_32):
    """Disassemble bytes and detect shellcode patterns"""
    md = Cs(arch, mode)
    instructions = []
    
    # Disassemble and collect instructions
    for ins in md.disasm(mem_bytes, base_addr):
        instructions.append(ins)
        print(f"0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}")
    
    # Detect shellcode patterns
    detector = ShellcodePatternDetector()
    patterns = detector.detect_patterns(instructions)
    
    if patterns:
        print("\n[!] SHELLCODE PATTERNS DETECTED:")
        for pattern in patterns:
            print(f"  - {pattern['pattern']}: {pattern['description']} (Severity: {pattern['severity']})")
    
    return {
        'instructions': instructions,
        'patterns': patterns,
        'total_instructions': len(instructions)
    }

# --- Analyze specific memory regions ---
def analyze_suspicious_region(mem_bytes, base_addr=0x1000):
    """Analyze a potentially suspicious memory region"""
    print(f"Analyzing memory region at 0x{base_addr:x} (size: {len(mem_bytes)} bytes)")
    
    # Check for common shellcode signatures
    signatures = {
        'metasploit': b'\xfc\xe8',
        'nop_sled': b'\x90\x90\x90\x90',
        'jmp_loop': b'\xeb\xfe',
        'xor_key': b'\x31\xc0',  # xor eax, eax
    }
    
    found_signatures = []
    for sig_name, sig_bytes in signatures.items():
        if mem_bytes.find(sig_bytes) != -1:
            found_signatures.append(sig_name)
    
    if found_signatures:
        print(f"[!] Found signatures: {', '.join(found_signatures)}")
    
    # Disassemble and analyze
    result = disassemble_bytes(mem_bytes, base_addr)
    
    return {
        'signatures': found_signatures,
        'patterns': result['patterns'],
        'instruction_count': result['total_instructions']
    }

# --- Cross-platform architecture detection ---
def detect_architecture(mem_bytes):
    """Detect the most likely architecture for the given bytes"""
    # Try different architectures
    architectures = [
        (CS_ARCH_X86, CS_MODE_32),
        (CS_ARCH_X86, CS_MODE_64),
        (CS_ARCH_ARM, CS_MODE_ARM),
        (CS_ARCH_ARM, CS_MODE_THUMB),
    ]
    
    for arch, mode in architectures:
        try:
            md = Cs(arch, mode)
            # Try to disassemble first few bytes
            count = 0
            for ins in md.disasm(mem_bytes[:64], 0x1000):
                count += 1
                if count >= 3:  # If we can disassemble at least 3 instructions
                    return arch, mode
        except:
            continue
    
    # Default to x86-64 if detection fails
    return CS_ARCH_X86, CS_MODE_64

# Example usage
if __name__ == "__main__":
    # Example: disassemble dummy bytes with shellcode patterns
    code = b"\x55\x48\x8b\x05\xb8\x13\x00\x00\x90\x90\x90\x90\xeb\xfe"  # x86_64 with NOP sled
    print("Analyzing sample shellcode:")
    result = analyze_suspicious_region(code, base_addr=0x1000)
    
    print(f"\nAnalysis Summary:")
    print(f"- Signatures found: {result['signatures']}")
    print(f"- Patterns detected: {len(result['patterns'])}")
    print(f"- Instructions analyzed: {result['instruction_count']}") 