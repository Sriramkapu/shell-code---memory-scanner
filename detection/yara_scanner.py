# yara_scanner.py
# YARA-based live memory scanner (Python template)
import yara
import psutil
import ctypes
import ctypes.wintypes
import os
import sys

# --- Compile YARA rules ---
def load_rules(rule_path):
    return yara.compile(filepath=rule_path)

# --- Windows-specific memory reading ---
def read_process_memory_windows(pid):
    """Read process memory on Windows using ReadProcessMemory"""
    try:
        # Get process handle
        process_handle = ctypes.windll.kernel32.OpenProcess(
            0x10,  # PROCESS_VM_READ
            False,
            pid
        )
        
        if not process_handle:
            return None
            
        # Get memory info
        memory_info = ctypes.wintypes.MEMORY_BASIC_INFORMATION()
        address = 0
        memory_regions = []
        
        while True:
            result = ctypes.windll.kernel32.VirtualQueryEx(
                process_handle,
                address,
                ctypes.byref(memory_info),
                ctypes.sizeof(memory_info)
            )
            
            if result == 0:
                break
                
            # Only read committed, readable memory regions
            if (memory_info.State == 0x1000 and  # MEM_COMMIT
                memory_info.Protect & 0x01):     # PAGE_READABLE
                
                try:
                    # Read memory region
                    buffer = ctypes.create_string_buffer(memory_info.RegionSize)
                    bytes_read = ctypes.wintypes.DWORD()
                    
                    success = ctypes.windll.kernel32.ReadProcessMemory(
                        process_handle,
                        memory_info.BaseAddress,
                        buffer,
                        memory_info.RegionSize,
                        ctypes.byref(bytes_read)
                    )
                    
                    if success and bytes_read.value > 0:
                        memory_regions.append(buffer.raw[:bytes_read.value])
                        
                except Exception:
                    pass  # Skip regions we can't read
                    
            address = memory_info.BaseAddress + memory_info.RegionSize
            
        ctypes.windll.kernel32.CloseHandle(process_handle)
        return memory_regions
        
    except Exception as e:
        print(f"Error reading Windows process memory: {e}")
        return None

# --- Linux-specific memory reading ---
def read_process_memory_linux(pid):
    """Read process memory on Linux using /proc filesystem"""
    try:
        memory_regions = []
        maps_path = f"/proc/{pid}/maps"
        mem_path = f"/proc/{pid}/mem"
        
        if not os.path.exists(maps_path):
            return None
            
        with open(maps_path, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 5:
                    continue
                    
                # Parse memory region info
                addr_range = parts[0]
                permissions = parts[1]
                
                # Only read readable regions
                if 'r' not in permissions:
                    continue
                    
                # Parse address range
                start_addr, end_addr = addr_range.split('-')
                start_addr = int(start_addr, 16)
                end_addr = int(end_addr, 16)
                size = end_addr - start_addr
                
                if size > 0 and size <= 1024*1024*10:  # Max 10MB per region
                    try:
                        with open(mem_path, 'rb') as mem_file:
                            mem_file.seek(start_addr)
                            data = mem_file.read(size)
                            if data:
                                memory_regions.append(data)
                    except Exception:
                        pass  # Skip regions we can't read
                        
        return memory_regions
        
    except Exception as e:
        print(f"Error reading Linux process memory: {e}")
        return None

# --- Cross-platform memory reading ---
def read_process_memory(pid):
    """Read process memory cross-platform"""
    if sys.platform.startswith('win'):
        return read_process_memory_windows(pid)
    elif sys.platform.startswith('linux'):
        return read_process_memory_linux(pid)
    else:
        print(f"Unsupported platform: {sys.platform}")
        return None

# --- Scan process memory ---
def scan_process(pid, rules):
    """Scan process memory with YARA rules"""
    print(f"Scanning PID {pid}...")
    
    # Read process memory
    memory_regions = read_process_memory(pid)
    if not memory_regions:
        print(f"Could not read memory for PID {pid}")
        return []
    
    # Scan each memory region
    all_matches = []
    for i, mem_bytes in enumerate(memory_regions):
        try:
            matches = rules.match(data=mem_bytes)
            if matches:
                print(f"Found matches in memory region {i} (size: {len(mem_bytes)} bytes)")
                for match in matches:
                    match.region_index = i
                    match.region_size = len(mem_bytes)
                all_matches.extend(matches)
        except Exception as e:
            print(f"Error scanning memory region {i}: {e}")
            continue
    
    return all_matches

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python yara_scanner.py <pid> <rules.yar>")
        exit(1)
    pid = int(sys.argv[1])
    rules = load_rules(sys.argv[2])
    results = scan_process(pid, rules)
    print("Matches:", results) 