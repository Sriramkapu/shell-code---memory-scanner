"""
Security utilities for process control and permission checks
"""
import os
import sys
import platform
import psutil
import hashlib


def check_admin_privileges():
    """
    Check if running with administrator/root privileges
    
    Returns:
        tuple: (has_privileges: bool, platform: str)
    """
    system = platform.system()
    
    if system == 'Windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0, 'Windows'
        except Exception:
            return False, 'Windows'
    
    elif system == 'Linux' or system == 'Darwin':  # Linux or macOS
        return os.geteuid() == 0, system
    
    return False, system


def can_terminate_process(pid):
    """
    Check if we have permission to terminate a process
    
    Args:
        pid: Process ID to check
    
    Returns:
        tuple: (can_terminate: bool, reason: str)
    """
    if pid == os.getpid():
        return False, "Cannot terminate self"
    
    try:
        proc = psutil.Process(pid)
        
        # Check if process exists
        if not proc.is_running():
            return False, "Process not running"
        
        # Check if we can access the process
        try:
            proc.status()
        except psutil.AccessDenied:
            return False, "Access denied - insufficient privileges"
        
        # Check if it's a critical system process (Windows)
        if platform.system() == 'Windows':
            critical_processes = {
                'csrss.exe', 'lsass.exe', 'smss.exe', 'winlogon.exe',
                'services.exe', 'system', 'dwm.exe'
            }
            if proc.name().lower() in critical_processes:
                return False, f"Critical system process: {proc.name()}"
        
        # Check if it's init/systemd (Linux)
        if platform.system() == 'Linux' and pid == 1:
            return False, "Cannot terminate init process"
        
        return True, "OK"
    
    except psutil.NoSuchProcess:
        return False, "Process not found"
    except Exception as e:
        return False, f"Error checking process: {str(e)}"


def safe_terminate_process(pid, timeout=5):
    """
    Safely terminate a process with permission checks
    
    Args:
        pid: Process ID to terminate
        timeout: Timeout in seconds before force kill
    
    Returns:
        tuple: (success: bool, action: str, reason: str)
    """
    can_term, reason = can_terminate_process(pid)
    
    if not can_term:
        return False, "Blocked (permission denied)", reason
    
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        
        # Try graceful termination first
        try:
            proc.terminate()
            proc.wait(timeout=timeout)
            return True, "Blocked (terminated)", f"Gracefully terminated {proc_name}"
        except psutil.TimeoutExpired:
            # Force kill if graceful termination failed
            try:
                proc.kill()
                proc.wait(timeout=2)
                return True, "Blocked (force killed)", f"Force killed {proc_name}"
            except Exception as e:
                return False, "Blocked (failed)", f"Failed to kill: {str(e)}"
    
    except psutil.NoSuchProcess:
        return False, "Blocked (stub)", "Process already terminated"
    except psutil.AccessDenied:
        return False, "Blocked (access denied)", "Insufficient privileges to terminate"
    except Exception as e:
        return False, "Blocked (error)", f"Error: {str(e)}"


def compute_sha256(file_path):
    """
    Compute SHA256 hash of a file
    
    Args:
        file_path: Path to file
    
    Returns:
        str: SHA256 hash in hex format, or None if error
    """
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error computing SHA256 for {file_path}: {e}")
        return None


def verify_file_integrity(file_path, expected_hash=None):
    """
    Verify file integrity using SHA256
    
    Args:
        file_path: Path to file to verify
        expected_hash: Optional expected SHA256 hash
    
    Returns:
        tuple: (is_valid: bool, computed_hash: str, message: str)
    """
    if not os.path.exists(file_path):
        return False, None, "File does not exist"
    
    computed_hash = compute_sha256(file_path)
    
    if computed_hash is None:
        return False, None, "Failed to compute hash"
    
    if expected_hash:
        if computed_hash.lower() == expected_hash.lower():
            return True, computed_hash, "Hash matches expected value"
        else:
            return False, computed_hash, "Hash mismatch - file may be tampered"
    
    return True, computed_hash, "Hash computed successfully"

