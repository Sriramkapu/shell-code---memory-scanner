# Memory Shellcode Detection Framework

Enterprise-grade, multi-layered memory shellcode detection and response system.

## Modules
- **agent/monitor/agent_core.c**: C agent for process hooking, memory dumping, syscall tracing (with Python bindings)
- **detection/yara_scanner.py**: Python YARA memory scanner for live process analysis
- **detection/disassembler.py**: Capstone-based disassembler for shellcode pattern recognition

## Quickstart
1. Build the agent core (C):
   - Windows: `cl agent_core.c`
   - Linux: `gcc -shared -fPIC -o libagentcore.so agent_core.c`
2. Install Python dependencies:
   ```bash
   pip install yara-python psutil capstone
   ```
3. Run YARA scanner:
   ```bash
   python detection/yara_scanner.py <pid> <rules.yar>
   ```
4. Run disassembler:
   ```bash
   python detection/disassembler.py
   ``` 