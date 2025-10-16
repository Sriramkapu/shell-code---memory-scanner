import os
import sys


def write_text(path: str, text: str) -> None:
    with open(path, 'w', encoding='ascii') as f:
        f.write(text)


def write_hex_bytes(path: str, hex_str: str) -> None:
    data = bytes.fromhex(hex_str.replace('\n', ' ').replace('\t', ' ').strip())
    with open(path, 'wb') as f:
        f.write(data)


def create_test_files(base_dir: str) -> None:
    os.makedirs(base_dir, exist_ok=True)

    # 1) TEST_STRING.txt
    write_text(os.path.join(base_dir, 'TEST_STRING.txt'), 'THIS_IS_A_TEST_MALWARE_FILE')

    # 2) msf_shellcode.bin
    write_hex_bytes(
        os.path.join(base_dir, 'msf_shellcode.bin'),
        'FC E8 00 00 00 00 60 89 E5 31 C0 64 8B 50 30'
    )

    # 3) nop_sled.bin
    write_hex_bytes(
        os.path.join(base_dir, 'nop_sled.bin'),
        '90 90 90 90 EB FE'
    )

    # 3b) NOP sled + exec transfer (benign test vector)
    write_hex_bytes(
        os.path.join(base_dir, 'nop_sled_execjump.bin'),
        '90 90 90 90 90 90 90 90 FF E4'
    )

    # 4) fake_pe_stub.exe
    data = bytearray()
    data += b'MZ'
    data += b'\x90' * 58
    data += (0x80).to_bytes(4, 'little')
    data += b'\x00' * (0x80 - len(data))
    data += b'PE\x00\x00'
    with open(os.path.join(base_dir, 'fake_pe_stub.exe'), 'wb') as f:
        f.write(data)

    # 5) high_entropy.bin
    import os as _os
    with open(os.path.join(base_dir, 'high_entropy.bin'), 'wb') as f:
        f.write(_os.urandom(8192))

    # 6) suspicious_command.lnk (text surrogate for string tests)
    write_text(os.path.join(base_dir, 'suspicious_command.lnk'), 'cmd.exe /c calc.exe')

    # 7) dotnet_reflect.cs (source only)
    cs = (
        "using System;\n"
        "using System.Reflection;\n"
        "public class Program {\n"
        "    public static void Main() {\n"
        "        Assembly.Load(\"SomeAssembly\");\n"
        "        Type t = Type.GetType(\"System.String\");\n"
        "    }\n"
        "}\n"
    )
    write_text(os.path.join(base_dir, 'dotnet_reflect.cs'), cs)

    # 8) syscall_setup.bin (benign test vector containing syscall bytes)
    write_hex_bytes(
        os.path.join(base_dir, 'syscall_setup.bin'),
        '48 C7 C0 2A 00 00 00 0F 05'
    )


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else 'test_samples'
    create_test_files(target)
    print(f"Created test samples in: {os.path.abspath(target)}")
    print("Scan with: yara -r config/yara_rules/sample_shellcode.yar " + os.path.abspath(target))


if __name__ == '__main__':
    main()


