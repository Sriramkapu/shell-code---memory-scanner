# YARA Rule Design Guide

## Rule Naming Convention

Rules follow a hierarchical naming pattern:
- `Shellcode_<Family>_<Pattern>` - Shellcode detection rules
- `Loader_<Type>_<Indicator>` - Loader/injection detection
- `Malware_<Family>_<Signature>` - Specific malware families
- `Test_<Description>` - Test/demo rules

## Optimized Rule Examples

### Example 1: Efficient String Matching

```yara
rule Shellcode_XOR_Decryption_Loop_Optimized
{
    meta:
        description = "XOR decryption loop pattern with optimized string matching"
        author = "detection-team"
        severity = "High"
        category = "Shellcode"
        reference = "https://example.com/xor-decryption"
    
    strings:
        // Use 'fullword' for better performance (avoids partial matches)
        // Use 'nocase' only when necessary (adds overhead)
        // Use 'wide' for Unicode strings (adds overhead)
        
        // XOR loop pattern: 33 C0 (xor eax, eax) or 31 C0 (xor eax, eax)
        $xor1 = { 33 C0 }  // xor eax, eax
        $xor2 = { 31 C0 }  // xor eax, eax (alternative encoding)
        
        // XOR with register: 33 C? (xor eax, reg)
        $xor_reg = { 33 C? }
        
        // LOOP instruction: E2 ??
        $loop = { E2 ?? }
        
        // CMP instruction: 3B C? (cmp eax, reg)
        $cmp = { 3B C? }
        
        // Optimized: Use 'any of' for multiple patterns
        $xor_patterns = { 33 C0 } | { 31 C0 } | { 33 C? }
    
    condition:
        // Efficient condition: Require XOR pattern + loop
        // 'any of' evaluates OR conditions efficiently
        any of ($xor*) and $loop
        
        // Alternative: Require multiple indicators (reduces false positives)
        // 2 of ($xor*) and $loop
}
```

### Example 2: Metasploit Pattern Detection

```yara
rule Shellcode_Metasploit_Common_Patterns
{
    meta:
        description = "Metasploit framework shellcode patterns"
        author = "detection-team"
        severity = "High"
        category = "Shellcode"
        reference = "https://github.com/rapid7/metasploit-framework"
    
    strings:
        // Metasploit prologue: FC E8 00 00 00 00 60 89 E5 31 C0 64 8B 50 30
        // FC = CLD (clear direction flag)
        // E8 00 00 00 00 = CALL $+5 (call-pop pattern)
        $prologue = { FC E8 00 00 00 00 60 89 E5 31 C0 64 8B 50 30 }
        
        // Windows API hash pattern (common in Metasploit)
        // 68 ?? ?? ?? ?? (push hash) + 58 (pop eax)
        $hash_push = { 68 ?? ?? ?? ?? 58 }
        
        // GetProcAddress pattern
        $getproc = { FF 14 85 ?? ?? ?? ?? }  // call dword ptr [eax*4+offset]
        
        // LoadLibrary pattern
        $loadlib = { FF 50 ?? }  // call dword ptr [eax+offset]
        
        // Optimized: Use condition with 'for any of' for efficiency
        $api_patterns = { FF 14 85 ?? ?? ?? ?? } | { FF 50 ?? }
    
    condition:
        // Require prologue + at least one API pattern
        $prologue and any of ($api_patterns)
        
        // Alternative stricter condition (reduces false positives):
        // $prologue and 2 of ($api_patterns)
}
```

### Example 3: Efficient Multi-String Rule

```yara
rule Shellcode_Loader_APIs_Optimized
{
    meta:
        description = "Loader APIs with optimized string matching"
        severity = "High"
        category = "Injection"
    
    strings:
        // Use 'ascii fullword' for exact matches (better performance)
        $a1 = "VirtualAlloc" ascii fullword nocase
        $a2 = "VirtualProtect" ascii fullword nocase
        $a3 = "WriteProcessMemory" ascii fullword nocase
        $a4 = "CreateRemoteThread" ascii fullword nocase
        $a5 = "RtlMoveMemory" ascii fullword nocase
        
        // Use hex patterns for obfuscated strings
        $hex_alloc = { 56 69 72 74 75 61 6C 41 6C 6C 6F 63 }  // "VirtualAlloc" in hex
    
    condition:
        // Efficient: Use 'for any of' with wildcard
        // This evaluates efficiently: checks each string once
        for any of ($a*) : ( $ at entrypoint or $ at entrypoint + 0x100 )
        
        // Alternative: Require multiple indicators
        // 2 of ($a*)  // At least 2 API strings
        
        // Most efficient: Use 'any of' operator
        // any of ($a*)  // Any API string matches
}
```

### Example 4: PE-Specific Rule

```yara
rule Shellcode_High_Entropy_Sections
{
    meta:
        description = "High entropy PE sections (packed/encrypted)"
        severity = "Medium"
        category = "Packing"
    
    strings:
        // Common packed section names
        $sect1 = ".upx" ascii fullword
        $sect2 = ".packed" ascii fullword
        $sect3 = ".aspack" ascii fullword
        $sect4 = ".vmp" ascii fullword
    
    condition:
        // Use PE module for PE-specific checks
        pe.number_of_sections > 5 and
        (
            // Check entropy using PE module
            for any section in pe.sections : (
                section.entropy > 7.0 and
                section.name matches /\.(text|data|rdata|rsrc)/
            )
        ) and
        (
            // Check for suspicious section names
            any of ($sect*) or
            // Check for multiple high-entropy sections
            (for any section in pe.sections : (section.entropy > 7.0)) >= 2
        )
}
```

## Performance Optimization Tips

### 1. String Matching Optimization

**Good:**
```yara
$s1 = "VirtualAlloc" ascii fullword nocase
```
- `fullword` prevents partial matches (faster)
- `nocase` only when needed (adds overhead)

**Better:**
```yara
$s1 = "VirtualAlloc" ascii fullword  // Case-sensitive is faster
```

**Best (for exact matches):**
```yara
$s1 = "VirtualAlloc" ascii  // No modifiers = fastest
```

### 2. Condition Optimization

**Inefficient:**
```yara
condition:
    $s1 or $s2 or $s3 or $s4 or $s5
```

**Efficient:**
```yara
condition:
    any of ($s*)
```

### 3. Hex Pattern Optimization

**Good:**
```yara
$pattern = { 90 90 90 90 EB FE }
```

**Better (with wildcards for flexibility):**
```yara
$pattern = { 90 90 90 90 EB FE ?? ?? }
```

**Best (if pattern varies):**
```yara
$pattern = { 90{4} EB FE }  // 4 NOPs, then jump
```

### 4. Use Rule Dependencies

```yara
import "pe"
import "hash"

rule Shellcode_Packed_PE
{
    meta:
        description = "Uses PE module for efficient checks"
    
    condition:
        pe.sections[0].entropy > 7.0 and
        pe.number_of_sections < 3
}
```

## Rule Validation Checklist

- [ ] Uses `fullword` for string matching when appropriate
- [ ] Avoids unnecessary `nocase` and `wide` modifiers
- [ ] Uses `any of ($*)` for multiple string checks
- [ ] Includes metadata (description, severity, category)
- [ ] Tests rule against known good/bad samples
- [ ] Validates rule compiles without errors
- [ ] Checks for false positives on clean samples

## Rule Compilation Validation

Rules are validated on startup:
```python
from utils.yara_validator import validate_yara_rules

validation = validate_yara_rules('config/yara_rules/sample_shellcode.yar')
if not validation['valid']:
    print(f"Validation errors: {validation['errors']}")
```

Validation checks:
- Rule syntax correctness
- String pattern validity
- Condition logic
- Metadata completeness
- SHA256 integrity

