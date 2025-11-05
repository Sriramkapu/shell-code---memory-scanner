# Platform-Specific Implementation Details

## Memory Dumping Implementation

### Windows Implementation

**APIs Used:**
- `OpenProcess()` - Opens process handle with PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
- `VirtualQueryEx()` - Queries memory regions in target process
- `ReadProcessMemory()` - Reads memory from target process into buffer

**Flow:**
```
1. OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, pid)
2. VirtualQueryEx() to enumerate memory regions
3. Filter for MEM_COMMIT + PAGE_READABLE regions
4. ReadProcessMemory() for each readable region
5. Write to output file
6. CloseHandle() cleanup
```

**Requirements:**
- Administrator privileges (SeDebugPrivilege)
- Process must exist and be accessible
- Target process must have readable memory regions

**Limitations:**
- Cannot read protected system processes (e.g., csrss.exe, lsass.exe)
- Large address space processes may require multiple reads
- Some memory regions may be inaccessible even with privileges

### Linux Implementation

**APIs/Filesystem Used:**
- `/proc/<pid>/maps` - Memory region layout
- `/proc/<pid>/mem` - Direct memory access
- `ptrace()` - Process attachment (for syscall tracing)

**Flow:**
```
1. Open /proc/<pid>/maps for memory layout
2. Parse map entries (start-end addresses, permissions)
3. Filter for readable regions (r flag)
4. Open /proc/<pid>/mem for memory content
5. fseek() to region start address
6. fread() memory content into buffer
7. Write to output file
8. Limit region size to 10MB per region
```

**Requirements:**
- Root privileges OR CAP_SYS_PTRACE capability
- Process must exist
- /proc filesystem must be mounted

**Capabilities Setup:**
```bash
# Grant CAP_SYS_PTRACE capability
sudo setcap cap_sys_ptrace+ep /path/to/detection-engine

# Or run as root
sudo python detection/orchestrator.py
```

**Limitations:**
- Cannot read memory of init process (PID 1)
- Requires ptrace capability or root
- Some kernel-protected memory may be inaccessible

### macOS Implementation (Planned)

**APIs to Use:**
- `mach_vm_read()` - Read memory via Mach VM API
- `mach_vm_region()` - Enumerate memory regions
- `task_for_pid()` - Get task port for process

**Requirements:**
- Root privileges (or System Integrity Protection bypass)
- Task port access permission

## Process Termination Security

### Windows Process Termination

**APIs Used:**
- `OpenProcess()` - Open process handle
- `TerminateProcess()` - Terminate process
- `GetLastError()` - Error handling

**Critical Process Protection:**
The following processes are protected from termination:
- `csrss.exe` - Client/Server Runtime Subsystem
- `lsass.exe` - Local Security Authority Subsystem
- `smss.exe` - Session Manager Subsystem
- `winlogon.exe` - Windows Logon Process
- `services.exe` - Service Control Manager
- `system` - System process
- `dwm.exe` - Desktop Window Manager

**Error Handling:**
- `ERROR_ACCESS_DENIED` - Insufficient privileges
- `ERROR_INVALID_PARAMETER` - Process doesn't exist
- Graceful fallback: Log warning, continue operation

### Linux Process Termination

**APIs Used:**
- `kill(pid, SIGTERM)` - Graceful termination
- `kill(pid, SIGKILL)` - Force termination (if SIGTERM fails)

**Protected Processes:**
- PID 1 (init/systemd) - Cannot be terminated
- Kernel threads - Protected by kernel

**Capability Requirements:**
- No special capability needed for user processes
- Root required for system processes

## Syscall Tracing

### Linux ptrace Implementation

**Syscalls Monitored:**
- `mprotect` (syscall 10) - Memory protection changes
- `mmap` (syscall 9) - Memory mapping
- `munmap` (syscall 11) - Memory unmapping

**Flow:**
```
1. PTRACE_ATTACH to target process
2. Wait for process to stop
3. PTRACE_SETOPTIONS with PTRACE_O_TRACESYSGOOD
4. Loop:
   - PTRACE_SYSCALL to wait for syscall entry
   - PTRACE_GETREGS to read syscall number
   - Check if syscall matches monitored set
   - PTRACE_SYSCALL for syscall exit
5. PTRACE_DETACH when done
```

**Requirements:**
- CAP_SYS_PTRACE capability or root
- Process must be traceable (not protected by YAMA)

### Windows API Hooking (Planned)

**APIs to Monitor:**
- `VirtualAlloc` - Memory allocation
- `VirtualProtect` - Memory protection changes
- `WriteProcessMemory` - Memory writes
- `CreateRemoteThread` - Thread injection

**Implementation Method:**
- DLL injection into target process
- IAT (Import Address Table) hooking
- Hook function prologues

## Performance Considerations

### Memory Dumping Performance

**Windows:**
- Average: ~50-100ms per process (depending on memory size)
- Large processes (>1GB): ~500ms-1s
- Bottleneck: ReadProcessMemory() syscall overhead

**Linux:**
- Average: ~30-80ms per process
- Large processes: ~300-800ms
- Bottleneck: /proc filesystem read overhead

### Optimization Strategies

1. **Limit Memory Regions**: Skip large non-executable regions
2. **Parallel Processing**: Dump multiple processes concurrently
3. **Caching**: Cache memory region information
4. **Sampling**: Only dump suspicious memory regions

## Error Handling

### Common Errors

**Windows:**
- `ERROR_ACCESS_DENIED` - Insufficient privileges → Log warning, skip process
- `ERROR_INVALID_PARAMETER` - Process doesn't exist → Skip process
- `ERROR_PARTIAL_COPY` - Partial memory read → Log warning, continue

**Linux:**
- `EACCES` - Permission denied → Log warning, skip process
- `ESRCH` - Process doesn't exist → Skip process
- `EPERM` - Operation not permitted → Log warning, skip process

### Graceful Degradation

The system implements graceful degradation:
1. Try C agent library first
2. Fall back to Python stub if library unavailable
3. Log warnings but continue operation
4. Never crash on single process failure

