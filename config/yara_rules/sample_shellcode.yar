rule Shellcode_Metasploit
{
    meta:
        description = "Detects common Metasploit shellcode patterns"
    strings:
        $a = { FC E8 ?? ?? ?? ?? 60 89 E5 31 C0 64 8B 50 30 } // typical shellcode stub
    condition:
        $a
}

rule Test_NOP_Sled
{
    meta:
        description = "Detects NOP sled + infinite loop (test pattern)"
    strings:
        $a = { 90 90 90 90 EB FE }
    condition:
        $a
}

rule Test_Malware_File
{
    strings:
        $test_string = "THIS_IS_A_TEST_MALWARE_FILE"
    condition:
        $test_string
} 