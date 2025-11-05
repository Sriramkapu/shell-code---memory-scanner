// Expanded YARA ruleset for testing and demonstrations
// Includes: simple test string, metasploit shellcode stub, NOP sled,
// PE signature checks, common payload strings, and hash IOC placeholder.

import "pe"
import "hash"
import "math"

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

// ============================================================================
// ENHANCED RULES - Enterprise-grade detection rules
// ============================================================================

rule Shellcode_NOP_Sled_Detection
{
    meta:
        author = "Security Research Team"
        description = "Detects NOP sleds commonly used in shellcode for landing pads"
        severity = "high"
        category = "shellcode"
        date = "2025-11-05"
        version = "1.0"
    strings:
        $nop_std_16 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $nop_std_32 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 
                        90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $alt_nop_0c = { 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C }
        $alt_nop_0d = { 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D }
        $multi_nop1 = { 66 90 66 90 66 90 66 90 }
        $multi_nop2 = { 0F 1F 00 0F 1F 00 }
    condition:
        any of ($nop_std*) or any of ($alt_nop*) or any of ($multi_nop*)
}

rule Shellcode_XOR_Decryption_Loop
{
    meta:
        author = "Security Research Team"
        description = "Detects XOR-based payload decryption loops common in shellcode"
        severity = "high"
        category = "shellcode"
        date = "2025-11-05"
        version = "1.0"
    strings:
        $xor_byte_al = { 30 ?? }
        $xor_word = { 31 ?? }
        $xor_immediate = { 80 ?? ?? }
        $xor_eax = { 35 ?? ?? ?? ?? }
        $loop_simple = { E2 ?? }
        $loopz = { E1 ?? }
        $loopnz = { E0 ?? }
        $inc_counter = { 40 }
        $dec_counter = { 48 }
        $add_counter = { 83 C? 01 }
    condition:
        (any of ($xor_byte_al, $xor_word, $xor_immediate, $xor_eax) and 
         any of ($loop_simple, $loopz, $loopnz) and 
         any of ($inc_counter, $dec_counter, $add_counter))
}

rule Shellcode_Call_Pop_Technique
{
    meta:
        author = "Security Research Team"
        description = "Detects call-pop technique for position-independent address resolution"
        severity = "high"
        category = "shellcode"
        date = "2025-11-05"
        version = "1.0"
    strings:
        $call_pop_eax = { E8 00 00 00 00 58 }
        $call_pop_ebx = { E8 00 00 00 00 5B }
        $call_pop_ecx = { E8 00 00 00 00 59 }
        $call_pop_edx = { E8 00 00 00 00 5A }
        $call_pop_esi = { E8 00 00 00 00 5E }
        $call_pop_edi = { E8 00 00 00 00 5F }
        $call_pop_ebp = { E8 00 00 00 00 5D }
        $call_offset_pop = { E8 ?? ?? ?? ?? 5? }
        $jmp_call_pop = { EB 03 E8 ?? ?? ?? ?? 5? }
    condition:
        any of them
}

rule Shellcode_Stack_Pivot
{
    meta:
        author = "Security Research Team"
        description = "Detects stack pivot techniques common in ROP chains and shellcode"
        severity = "critical"
        category = "exploitation"
        date = "2025-11-05"
        version = "1.0"
    strings:
        $mov_esp_reg = { 89 ?4 }
        $mov_esp_mem = { 8B ?? 24 }
        $mov_rsp = { 48 89 ?4 }
        $xchg_esp_eax = { 94 }
        $xchg_esp_reg = { 87 ?? }
        $lea_esp = { 8D 64 24 }
        $lea_esp_large = { 8D A4 24 }
        $sub_esp_large = { 81 EC ?? ?? ?? ?? }
        $add_esp_large = { 81 C4 ?? ?? ?? ?? }
        $mov_rsp_mem = { 48 8B ?? 24 }
        $xchg_rsp = { 48 87 ?? }
    condition:
        any of them
}

rule Shellcode_Metasploit_Common_Patterns
{
    meta:
        author = "Security Research Team"
        description = "Detects common Metasploit Framework shellcode signatures"
        severity = "critical"
        category = "malware"
        family = "Metasploit"
        date = "2025-11-05"
        version = "1.0"
    strings:
        $metsrv = "metsrv" ascii wide
        $meterpreter = "meterpreter" ascii wide
        $ws2_32 = "ws2_32" ascii wide nocase
        $socket_setup = { 6A 00 6A 01 6A 02 }
        $socket_call = { FF 15 ?? ?? ?? ?? }
        $connect_setup = { 5F 6A 10 }
        $bin_sh = { 2F 2F 62 69 6E 2F 73 68 }
        $bin_bash = { 2F 62 69 6E 2F 62 61 73 68 }
        $execve_setup = { 6A 0B 58 99 }
    condition:
        2 of them
}

rule Shellcode_Metasploit_Reverse_TCP
{
    meta:
        author = "Security Research Team"
        description = "Detects Metasploit reverse TCP shellcode patterns"
        severity = "critical"
        category = "malware"
        family = "Metasploit"
        date = "2025-11-05"
        version = "1.1"
    strings:
        $reverse_tcp_init = { FC E8 ?? ?? 00 00 60 }
        $wsastartup = { 6A 01 6A 02 }
        $socket_create = { 6A 06 6A 01 6A 02 }
        $connect_struct = { 68 ?? ?? ?? ?? 66 68 ?? ?? }
        $recv_loop = { 6A 00 6A ?? 5? FF }
    condition:
        2 of them or $reverse_tcp_init
}

rule Shellcode_Process_Injection_APIs
{
    meta:
        author = "Security Research Team"
        description = "Detects process injection via suspicious API import sequences"
        severity = "critical"
        category = "injection"
        date = "2025-11-05"
        version = "1.0"
    condition:
        pe.is_pe and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        (
            pe.imports("kernel32.dll", "CreateRemoteThread") or
            pe.imports("ntdll.dll", "NtCreateThreadEx") or
            pe.imports("kernel32.dll", "QueueUserAPC")
        )
}

rule Shellcode_Suspicious_Memory_APIs
{
    meta:
        author = "Security Research Team"
        description = "Detects suspicious memory allocation API combinations"
        severity = "high"
        category = "injection"
        date = "2025-11-05"
        version = "1.0"
    condition:
        pe.is_pe and
        (
            pe.imports("kernel32.dll", "VirtualAlloc") or
            pe.imports("kernel32.dll", "VirtualAllocEx")
        ) and
        (
            pe.imports("kernel32.dll", "VirtualProtect") or
            pe.imports("kernel32.dll", "VirtualProtectEx")
        ) and
        (
            pe.imports("kernel32.dll", "CreateThread") or
            pe.imports("kernel32.dll", "CreateRemoteThread")
        )
}

rule Shellcode_Direct_Syscalls
{
    meta:
        author = "Security Research Team"
        description = "Detects direct syscall instructions used for EDR evasion"
        severity = "high"
        category = "evasion"
        date = "2025-11-05"
        version = "1.0"
    strings:
        $syscall_x64 = { 0F 05 }
        $syscall_x86 = { CD 2E }
        $sysenter = { 0F 34 }
        $syscall_setup = { B8 ?? ?? ?? ?? 0F 05 }
        $syscall_params = { 4C 8B ?? ?? 49 ?? ?? B8 ?? ?? ?? ?? 0F 05 }
    condition:
        any of them
}

rule Shellcode_ROR13_API_Hashing
{
    meta:
        author = "Security Research Team"
        description = "Detects ROR13 API hashing technique (Metasploit/Cobalt Strike)"
        severity = "high"
        category = "evasion"
        date = "2025-11-05"
        version = "1.0"
    strings:
        $ror13_cl = { C1 C? 0D }
        $ror13_ror = { D3 C? }
        $hash_compare = { 81 F? ?? ?? ?? ?? 74 }
        $hash_cmp = { 39 ?? 74 }
        $peb_walk = { 64 8B ?? 30 }
        $peb_walk_x64 = { 65 48 8B ?? 60 }
        $ldr_walk = { 8B ?? 0C }
    condition:
        (any of ($ror13_cl, $ror13_ror) and 
         any of ($hash_compare, $hash_cmp) and 
         (any of ($peb_walk, $peb_walk_x64) or $ldr_walk))
}

rule Shellcode_Shikata_Ga_Nai_Encoder
{
    meta:
        author = "Security Research Team"
        description = "Detects Shikata Ga Nai polymorphic encoder (Metasploit)"
        severity = "critical"
        category = "encoder"
        family = "Metasploit"
        date = "2025-11-05"
        version = "1.0"
    strings:
        $fpu_d9 = { D9 ?? }
        $fnstenv = { D9 74 24 F4 }
        $xor_loop1 = { 31 ?? 83 ?? ?? E2 }
        $xor_loop2 = { 31 ?? ?? 03 ?? ?? E2 }
    condition:
        (any of ($fpu_d9, $fnstenv) and any of ($xor_loop1, $xor_loop2)) or
        ($fnstenv and $xor_loop1)
}

rule Shellcode_High_Entropy_Sections
{
    meta:
        author = "Security Research Team"
        description = "Detects high entropy PE sections indicating packing or encryption"
        severity = "medium"
        category = "packer"
        date = "2025-11-05"
        version = "1.0"
    condition:
        pe.is_pe and
        for any i in (0..pe.number_of_sections-1): (
            math.entropy(
                pe.sections[i].raw_data_offset, 
                pe.sections[i].raw_data_size
            ) >= 7.5 and
            pe.sections[i].raw_data_size > 512
        )
}

rule Shellcode_Dynamic_API_Loading
{
    meta:
        author = "Security Research Team"
        description = "Detects minimal import table with only LoadLibrary and GetProcAddress"
        severity = "high"
        category = "evasion"
        date = "2025-11-05"
        version = "1.0"
    condition:
        pe.is_pe and 
        pe.number_of_imported_functions <= 4 and
        pe.imports("kernel32.dll", "GetProcAddress") and
        (
            pe.imports("kernel32.dll", "LoadLibraryA") or
            pe.imports("kernel32.dll", "LoadLibraryW") or
            pe.imports("kernel32.dll", "LoadLibraryExA") or
            pe.imports("kernel32.dll", "LoadLibraryExW")
        )
}

rule Shellcode_Cobalt_Strike_Beacon
{
    meta:
        author = "Security Research Team"
        description = "Detects Cobalt Strike Beacon shellcode patterns"
        severity = "critical"
        category = "malware"
        family = "CobaltStrike"
        date = "2025-11-05"
        version = "1.0"
    strings:
        $beacon_config = { 00 01 00 01 00 02 }
        $http_stager = "User-Agent:" ascii
        $https_stager = "HTTPS" ascii
        $named_pipe = "\\\\.\\pipe\\" ascii wide
        $hash_1 = { 56 A2 B5 F0 }
        $hash_2 = { E0 53 31 4B }
        $hash_3 = { 6C 1D 8F 0E }
        $sleep_mask = { 48 8B ?? ?? E8 ?? ?? ?? ?? }
    condition:
        2 of them
}

rule Shellcode_Reflective_DLL_Injection
{
    meta:
        author = "Security Research Team"
        description = "Detects reflective DLL injection techniques"
        severity = "critical"
        category = "injection"
        date = "2025-11-05"
        version = "1.0"
    strings:
        $reflective_loader = "ReflectiveLoader" ascii
        $dll_inject = "DllInject" ascii
        $mz_header_check = { 3C 5A 74 ?? 3C 4D 75 }
        $pe_sig_check = { 81 3? 50 45 00 00 }
        $valloc_call = { FF 15 ?? ?? ?? ?? 85 C0 74 }
        $get_proc_hash = { E8 ?? ?? ?? ?? 85 C0 74 }
    condition:
        (any of ($reflective_loader, $dll_inject) or
         ($mz_header_check and $pe_sig_check)) and
        ($valloc_call or $get_proc_hash)
}

rule Shellcode_Thread_Execution_Hijacking
{
    meta:
        author = "Security Research Team"
        description = "Detects thread execution hijacking techniques"
        severity = "high"
        category = "injection"
        date = "2025-11-05"
        version = "1.0"
    condition:
        pe.is_pe and
        (
            pe.imports("kernel32.dll", "SuspendThread") or
            pe.imports("ntdll.dll", "NtSuspendThread")
        ) and
        (
            pe.imports("kernel32.dll", "SetThreadContext") or
            pe.imports("ntdll.dll", "NtSetContextThread")
        ) and
        (
            pe.imports("kernel32.dll", "ResumeThread") or
            pe.imports("ntdll.dll", "NtResumeThread")
        )
}

rule Shellcode_Heap_Spray_Pattern
{
    meta:
        author = "Security Research Team"
        description = "Detects heap spray patterns in memory"
        severity = "high"
        category = "exploitation"
        date = "2025-11-05"
        version = "1.0"
    strings:
        $heap_nop_sled = { 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 
                           0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C }
        $js_spray1 = "%u9090%u9090" ascii
        $js_spray2 = "unescape" ascii
        $js_spray3 = ".substring(" ascii
        $addr_pattern = { 0D 0D 0D 0D 0D 0D 0D 0D }
    condition:
        any of them
}

rule Shellcode_Code_Cave_Indicators
{
    meta:
        author = "Security Research Team"
        description = "Detects potential code cave injection indicators"
        severity = "medium"
        category = "injection"
        date = "2025-11-05"
        version = "1.0"
    strings:
        $jmp_to_cave = { E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 }
        $call_to_cave = { E8 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 }
    condition:
        pe.is_pe and any of them
}

rule Shellcode_APC_Injection
{
    meta:
        author = "Security Research Team"
        description = "Detects Asynchronous Procedure Call (APC) injection"
        severity = "high"
        category = "injection"
        date = "2025-11-05"
        version = "1.0"
    condition:
        pe.is_pe and
        (
            pe.imports("kernel32.dll", "QueueUserAPC") or
            pe.imports("ntdll.dll", "NtQueueApcThread")
        ) and
        (
            pe.imports("kernel32.dll", "VirtualAllocEx") or
            pe.imports("ntdll.dll", "NtAllocateVirtualMemory")
        )
}

rule Shellcode_Suspicious_PE_Sections
{
    meta:
        author = "Security Research Team"
        description = "Detects PE files with suspicious non-standard section names"
        severity = "medium"
        category = "anomaly"
        date = "2025-11-05"
        version = "1.0"
    condition:
        pe.is_pe and
        for any i in (0..pe.number_of_sections-1): (
            not (
                pe.sections[i].name == ".text" or
                pe.sections[i].name == ".data" or
                pe.sections[i].name == ".rdata" or
                pe.sections[i].name == ".rsrc" or
                pe.sections[i].name == ".reloc" or
                pe.sections[i].name == ".idata" or
                pe.sections[i].name == ".edata" or
                pe.sections[i].name == ".pdata" or
                pe.sections[i].name == ".debug" or
                pe.sections[i].name == ".tls"
            ) and
            pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE
        )
}
