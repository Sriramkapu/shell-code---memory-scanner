"""
agent_bindings.py
Python bindings for agent_core C library

Supports both ctypes and CFFI loading methods
"""

import ctypes
import os
import platform

class AgentCore:
    """Python wrapper for agent_core C library"""
    
    def __init__(self):
        """Load agent_core shared library based on platform"""
        self.lib = None
        self._load_library()
    
    def _load_library(self):
        """Load platform-specific shared library"""
        system = platform.system()
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        if system == 'Windows':
            lib_path = os.path.join(base_dir, '..', '..', 'build', 'agent_core.dll')
        elif system == 'Linux':
            lib_path = os.path.join(base_dir, '..', '..', 'build', 'libagentcore.so')
        elif system == 'Darwin':  # macOS
            lib_path = os.path.join(base_dir, '..', '..', 'build', 'libagentcore.dylib')
        else:
            raise OSError(f"Unsupported platform: {system}")
        
        if not os.path.exists(lib_path):
            # Fallback to stub implementation
            print(f"[WARNING] Agent library not found at {lib_path}, using stub")
            return None
        
        try:
            self.lib = ctypes.CDLL(lib_path)
            
            # Define function signatures
            self.lib.py_hook_process.argtypes = []
            self.lib.py_hook_process.restype = None
            
            self.lib.py_dump_memory.argtypes = [ctypes.c_int, ctypes.c_char_p]
            self.lib.py_dump_memory.restype = ctypes.c_int
            
            self.lib.py_trace_syscalls.argtypes = [ctypes.c_int]
            self.lib.py_trace_syscalls.restype = None
            
            print(f"[OK] Loaded agent_core library: {lib_path}")
        except Exception as e:
            print(f"[WARNING] Failed to load agent library: {e}, using stub")
            self.lib = None
    
    def dump_memory(self, pid, out_path):
        """Dump process memory using C agent"""
        if self.lib is None:
            # Stub implementation for testing
            with open(out_path, 'wb') as f:
                f.write(b'\x90\x90\x90\x90\xeb\xfe' + b'\x00' * 1018)
            return True
        
        try:
            result = self.lib.py_dump_memory(pid, out_path.encode('utf-8'))
            return result == 1
        except Exception as e:
            print(f"[ERROR] Failed to dump memory: {e}")
            return False
    
    def hook_process(self):
        """Hook into process monitoring"""
        if self.lib is None:
            return False
        
        try:
            self.lib.py_hook_process()
            return True
        except Exception as e:
            print(f"[ERROR] Failed to hook process: {e}")
            return False
    
    def trace_syscalls(self, pid):
        """Trace syscalls for a process"""
        if self.lib is None:
            return False
        
        try:
            self.lib.py_trace_syscalls(pid)
            return True
        except Exception as e:
            print(f"[ERROR] Failed to trace syscalls: {e}")
            return False

