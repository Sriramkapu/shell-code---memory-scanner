/**
 * agent_core.h
 * C Agent Core API Header
 * 
 * Cross-platform memory dumping and process monitoring interface
 * Compatible with ctypes (Python) and CFFI bindings
 */

#ifndef AGENT_CORE_H
#define AGENT_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Hook into process monitoring system
 * 
 * Platform-specific implementations:
 * - Windows: ETW (Event Tracing for Windows) session for process events
 * - Linux: ptrace-based syscall monitoring
 * - macOS: Not yet implemented (requires Endpoint Security API)
 * 
 * @return 0 on success, -1 on failure
 */
void py_hook_process(void);

/**
 * @brief Dump process memory to file
 * 
 * Platform-specific implementations:
 * - Windows: Uses OpenProcess + ReadProcessMemory API
 *   - Opens process with PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
 *   - Iterates memory regions via VirtualQueryEx
 *   - Reads committed, readable pages only
 *   - Handles large address space (64-bit)
 * 
 * - Linux: Uses /proc/<pid>/mem filesystem
 *   - Reads /proc/<pid>/maps for memory layout
 *   - Accesses /proc/<pid>/mem for memory content
 *   - Requires CAP_SYS_PTRACE capability or root privileges
 *   - Filters readable regions (r flag in maps)
 *   - Limits region size to 10MB per region
 * 
 * - macOS: Not yet implemented (requires mach_vm_read API)
 * 
 * @param pid Process ID to dump
 * @param out_path Output file path for memory dump
 * @return 1 on success, 0 on failure
 */
int py_dump_memory(int pid, const char* out_path);

/**
 * @brief Trace syscalls for a process
 * 
 * Platform-specific implementations:
 * - Windows: API hooking (VirtualAlloc, VirtualProtect, CreateRemoteThread)
 *   - Requires DLL injection and IAT hooking
 *   - Monitors memory-related APIs
 * 
 * - Linux: ptrace-based syscall tracing
 *   - Attaches to process via PTRACE_ATTACH
 *   - Sets PTRACE_O_TRACESYSGOOD option
 *   - Monitors mprotect (10), mmap (9), munmap (11) syscalls
 *   - Uses user_regs_struct for register access
 * 
 * @param pid Process ID to trace
 */
void py_trace_syscalls(int pid);

#ifdef __cplusplus
}
#endif

#endif /* AGENT_CORE_H */

