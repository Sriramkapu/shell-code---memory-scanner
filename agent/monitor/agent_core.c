// agent_core.c
// Lightweight process monitor agent core (C template)
// Supports: Windows (ETW, ReadProcessMemory), Linux (procfs, ptrace)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#else
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#endif

// --- Process Hooking Implementation ---
void hook_process() {
#ifdef _WIN32
    // Windows: Use ETW (Event Tracing for Windows) for process monitoring
    printf("Windows process hooking via ETW (Event Tracing for Windows)\n");
    // TODO: Implement ETW session for process creation/termination events
    // This would require more complex ETW setup with manifest files
#else
    // Linux: Use ptrace for process monitoring
    printf("Linux process hooking via ptrace\n");
    // TODO: Implement ptrace-based process monitoring
    // This would require setting up ptrace hooks for syscalls
#endif
}

// --- Live Memory Dumping Implementation ---
int dump_memory(int pid, const char* out_path) {
#ifdef _WIN32
    // Windows: Use ReadProcessMemory API
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        printf("Failed to open process %d: %lu\n", pid, GetLastError());
        return 0;
    }
    
    // Get process memory info
    MEMORY_BASIC_INFORMATION mbi;
    DWORD_PTR address = 0;
    FILE* out_file = fopen(out_path, "wb");
    if (!out_file) {
        CloseHandle(hProcess);
        return 0;
    }
    
    while (VirtualQueryEx(hProcess, (LPVOID)address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect & PAGE_READABLE)) {
            
            // Read memory region
            BYTE* buffer = malloc(mbi.RegionSize);
            if (buffer) {
                SIZE_T bytes_read;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, &bytes_read)) {
                    fwrite(buffer, 1, bytes_read, out_file);
                }
                free(buffer);
            }
        }
        address = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
    }
    
    fclose(out_file);
    CloseHandle(hProcess);
    return 1;
    
#else
    // Linux: Use /proc filesystem
    char maps_path[256], mem_path[256];
    char line[1024];
    FILE* maps_file, *mem_file, *out_file;
    
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    
    maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        printf("Failed to open /proc/%d/maps\n", pid);
        return 0;
    }
    
    mem_file = fopen(mem_path, "rb");
    if (!mem_file) {
        fclose(maps_file);
        printf("Failed to open /proc/%d/mem\n", pid);
        return 0;
    }
    
    out_file = fopen(out_path, "wb");
    if (!out_file) {
        fclose(maps_file);
        fclose(mem_file);
        return 0;
    }
    
    while (fgets(line, sizeof(line), maps_file)) {
        unsigned long start, end;
        char perms[5];
        
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (strchr(perms, 'r')) {  // Readable region
                size_t size = end - start;
                if (size > 0 && size <= 10*1024*1024) {  // Max 10MB per region
                    char* buffer = malloc(size);
                    if (buffer) {
                        fseek(mem_file, start, SEEK_SET);
                        size_t bytes_read = fread(buffer, 1, size, mem_file);
                        if (bytes_read > 0) {
                            fwrite(buffer, 1, bytes_read, out_file);
                        }
                        free(buffer);
                    }
                }
            }
        }
    }
    
    fclose(maps_file);
    fclose(mem_file);
    fclose(out_file);
    return 1;
#endif
}

// --- Syscall Tracing Implementation ---
void trace_syscalls(int pid) {
#ifdef _WIN32
    // Windows: Monitor specific API calls via hooking
    printf("Windows syscall tracing via API hooking\n");
    // TODO: Implement API hooking for VirtualAlloc, VirtualProtect, etc.
    // This would require DLL injection and IAT hooking
#else
    // Linux: Use ptrace for syscall tracing
    printf("Linux syscall tracing via ptrace\n");
    
    // Attach to process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        printf("Failed to attach to process %d\n", pid);
        return;
    }
    
    int status;
    waitpid(pid, &status, 0);
    
    // Set options for syscall tracing
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
    
    // Monitor syscalls
    while (1) {
        // Wait for syscall entry
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) break;
        if (waitpid(pid, &status, 0) == -1) break;
        
        if (WIFEXITED(status)) break;
        
        // Get syscall number
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) break;
        
        // Monitor specific syscalls (mprotect, mmap, etc.)
        #ifdef __x86_64__
        long syscall_num = regs.orig_rax;
        #else
        long syscall_num = regs.orig_eax;
        #endif
        
        // Check for memory-related syscalls
        if (syscall_num == 10 ||  // mprotect
            syscall_num == 9 ||   // mmap
            syscall_num == 11) {  // munmap
            printf("Suspicious syscall %ld detected in PID %d\n", syscall_num, pid);
        }
        
        // Wait for syscall exit
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) break;
        if (waitpid(pid, &status, 0) == -1) break;
        
        if (WIFEXITED(status)) break;
    }
    
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
#endif
}

// --- Python Bindings Example (CFFI/ctypes compatible) ---
#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
__declspec(dllexport) void py_hook_process() { hook_process(); }
__declspec(dllexport) int py_dump_memory(int pid, const char* out_path) { return dump_memory(pid, out_path); }
__declspec(dllexport) void py_trace_syscalls(int pid) { trace_syscalls(pid); }
#else
void py_hook_process() { hook_process(); }
int py_dump_memory(int pid, const char* out_path) { return dump_memory(pid, out_path); }
void py_trace_syscalls(int pid) { trace_syscalls(pid); }
#endif

#ifdef __cplusplus
}
#endif 