// Expanded YARA ruleset for testing and demonstrations
// Includes: simple test string, metasploit shellcode stub, NOP sled,
// PE signature checks, common payload strings, and hash IOC placeholder.

import "pe"
import "hash"

rule Test_Malware_File
{
    meta:
        description = "Simple literal marker for testing end-to-end pipeline"
        author = "demo"
        severity = "Low"
        category = "Test"
    strings:
        $s1 = "THIS_IS_A_TEST_MALWARE_FILE" ascii nocase wide
    condition:
        $s1
}

rule Shellcode_Metasploit
{
    meta:
        description = "Metasploit-style shellcode prologue (stub bytes)"
        author = "demo"
        severity = "High"
        category = "Shellcode"
    strings:
        // fc e8 00 00 00 00 60 89 e5 31 c0 64 8b 50 30
        $stub = { FC E8 00 00 00 00 60 89 E5 31 C0 64 8B 50 30 }
    condition:
        $stub
}

rule Shellcode_NOP_Sled
{
    meta:
        description = "Short NOP sled followed by infinite loop (eb fe)"
        author = "demo"
        severity = "Medium"
        category = "Shellcode"
    strings:
        $sled = { 90 90 90 90 EB FE }
    condition:
        $sled
}

rule Common_Payload_and_Loader_Strings
{
    meta:
        description = "Common payload/loader indicator strings"
        author = "demo"
        severity = "Medium"
        category = "Heuristic"
    strings:
        $s1 = "powershell -enc" nocase ascii
        $s2 = "powershell -encodedcommand" nocase ascii
        $s3 = "VirtualAlloc" ascii
        $s4 = "CreateThread" ascii
        $s5 = "WriteProcessMemory" ascii
        $s6 = "rundll32" nocase ascii
        $s7 = "cmd.exe /c" nocase ascii
    condition:
        2 of ($s*)
}

rule Shellcode_Loader_APIs
{
    meta:
        description = "Loader APIs commonly used by shellcode loaders/injectors"
        severity = "High"
    strings:
        $a1 = "VirtualAlloc" ascii nocase
        $a2 = "VirtualProtect" ascii nocase
        $a3 = "WriteProcessMemory" ascii nocase
        $a4 = "CreateRemoteThread" ascii nocase
        $a5 = "RtlMoveMemory" ascii nocase
    condition:
        2 of ($a*)
}

rule Shellcode_NOP_Sled_ExecJump
{
    meta:
        description = "NOP sled followed by an immediate control transfer"
        severity = "High"
        category = "Shellcode"
    strings:
        $sled8 = { 90 90 90 90 90 90 90 90 }
        $jmp_eax = { FF E0 }
        $jmp_esp = { FF E4 }
        $call_rel = { E8 ?? ?? ?? ?? }
        $jmp_rel  = { E9 ?? ?? ?? ?? }
    condition:
        $sled8 and 1 of ($jmp_eax, $jmp_esp, $call_rel, $jmp_rel)
}

rule Shellcode_Syscall_Setup
{
    meta:
        description = "Syscall/INT setup sequences typical in shellcode"
        severity = "High"
        category = "Shellcode"
    strings:
        $linux_syscall = { 0F 05 }              // syscall (x86_64)
        $linux_int80   = { CD 80 }              // int 0x80 (x86)
        $win_sysenter  = { 0F 34 }              // sysenter (x86)
        $mov_rax_imm   = { 48 C7 C0 ?? ?? ?? ?? } // mov rax, imm32
        $xor_eax       = { 31 C0 }              // xor eax, eax
    condition:
        1 of ($linux_syscall, $linux_int80, $win_sysenter) and 1 of ($mov_rax_imm, $xor_eax)
}

rule Shellcode_RWX_Allocation_And_Write
{
    meta:
        description = "RWX allocations and write-to-exec API usage"
        severity = "Medium"
        category = "Heuristic"
    strings:
        $va   = "VirtualAlloc" ascii nocase
        $vp   = "VirtualProtect" ascii nocase
        $wpm  = "WriteProcessMemory" ascii nocase
        $rwx1 = "PAGE_EXECUTE_READWRITE" ascii nocase
        $rwx2 = "PAGE_EXECUTE_READ" ascii nocase
        $rwx3 = "MEM_COMMIT" ascii nocase
    condition:
        (2 of ($va, $vp, $wpm)) or (1 of ($va, $vp) and 1 of ($rwx*))
}

rule PE_Signature_Quick_Check
{
    meta:
        description = "Quick MZ header presence check (PE heuristic)"
    condition:
        uint16(0) == 0x5A4D
}

rule Known_Bad_File_By_Hash
{
    meta:
        description = "Hash matches known-bad sample (example)"
        severity = "High"
        category = "IOC"
    condition:
        hash.md5(0, filesize) == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
