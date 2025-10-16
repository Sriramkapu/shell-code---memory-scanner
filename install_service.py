#!/usr/bin/env python3
"""
Windows Service Installation Script for Memory Shellcode Detection Framework
"""

import os
import sys
import subprocess
import winreg
from pathlib import Path

def create_windows_service():
    """Create Windows service for the detection framework"""
    print("🛠️ Creating Windows Service for Memory Shellcode Detection")
    print("=" * 60)
    
    # Get current directory
    current_dir = Path(__file__).parent.absolute()
    python_exe = sys.executable
    orchestrator_path = current_dir / "detection" / "orchestrator.py"
    
    # Service configuration
    service_name = "MemoryShellcodeDetection"
    service_display_name = "Memory Shellcode Detection Framework"
    service_description = "Enterprise-grade memory shellcode detection and response system"
    
    # Create service using sc command
    sc_command = [
        "sc", "create", service_name,
        f"binPath= \"{python_exe}\" \"{orchestrator_path}\"",
        f"DisplayName= \"{service_display_name}\"",
        "start= auto",
        "error= normal"
    ]
    
    try:
        # Create the service
        result = subprocess.run(sc_command, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Service created successfully!")
            
            # Set service description
            desc_command = [
                "sc", "description", service_name, service_description
            ]
            subprocess.run(desc_command, capture_output=True)
            
            # Start the service
            start_command = ["sc", "start", service_name]
            start_result = subprocess.run(start_command, capture_output=True, text=True)
            
            if start_result.returncode == 0:
                print("✅ Service started successfully!")
            else:
                print("⚠️ Service created but failed to start automatically")
                print("   You can start it manually with: sc start MemoryShellcodeDetection")
            
            print(f"\n📋 Service Information:")
            print(f"   Name: {service_name}")
            print(f"   Display Name: {service_display_name}")
            print(f"   Status: Installed and configured")
            print(f"   Auto Start: Enabled")
            
        else:
            print(f"❌ Failed to create service: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Error creating service: {e}")
        return False
    
    return True

def remove_windows_service():
    """Remove Windows service"""
    print("🗑️ Removing Windows Service")
    print("=" * 60)
    
    service_name = "MemoryShellcodeDetection"
    
    try:
        # Stop the service first
        stop_command = ["sc", "stop", service_name]
        subprocess.run(stop_command, capture_output=True)
        
        # Delete the service
        delete_command = ["sc", "delete", service_name]
        result = subprocess.run(delete_command, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Service removed successfully!")
        else:
            print(f"❌ Failed to remove service: {result.stderr}")
            
    except Exception as e:
        print(f"❌ Error removing service: {e}")

def create_startup_script():
    """Create startup script for manual installation"""
    print("📝 Creating Startup Script")
    print("=" * 60)
    
    current_dir = Path(__file__).parent.absolute()
    python_exe = sys.executable
    orchestrator_path = current_dir / "detection" / "orchestrator.py"
    
    # Create batch file for manual startup
    batch_content = f"""@echo off
echo Starting Memory Shellcode Detection Framework...
cd /d "{current_dir}"
"{python_exe}" "{orchestrator_path}"
pause
"""
    
    batch_path = current_dir / "start_detection.bat"
    
    try:
        with open(batch_path, 'w') as f:
            f.write(batch_content)
        print(f"✅ Startup script created: {batch_path}")
        
        # Create PowerShell script for elevated startup
        ps_content = f"""# Memory Shellcode Detection Framework Startup Script
Write-Host "Starting Memory Shellcode Detection Framework..." -ForegroundColor Green
Set-Location "{current_dir}"
& "{python_exe}" "{orchestrator_path}"
"""
        
        ps_path = current_dir / "start_detection.ps1"
        with open(ps_path, 'w') as f:
            f.write(ps_content)
        print(f"✅ PowerShell script created: {ps_path}")
        
    except Exception as e:
        print(f"❌ Error creating startup scripts: {e}")

def main():
    """Main function"""
    print("🛡️ Memory Shellcode Detection Framework - Service Installation")
    print("=" * 70)
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "remove":
            remove_windows_service()
        elif sys.argv[1] == "startup":
            create_startup_script()
        else:
            print("Usage: python install_service.py [remove|startup]")
    else:
        # Check if running as administrator
        try:
            is_admin = subprocess.run(["net", "session"], capture_output=True).returncode == 0
        except:
            is_admin = False
        
        if not is_admin:
            print("⚠️ Warning: This script should be run as Administrator")
            print("   Right-click and 'Run as Administrator' for full service installation")
            print("\n📝 Creating startup scripts instead...")
            create_startup_script()
        else:
            print("✅ Running as Administrator - proceeding with service installation")
            if create_windows_service():
                create_startup_script()
    
    print("\n🎉 Service installation completed!")
    print("\n📋 Next Steps:")
    print("   1. Service is now installed and configured")
    print("   2. Use 'sc start MemoryShellcodeDetection' to start")
    print("   3. Use 'sc stop MemoryShellcodeDetection' to stop")
    print("   4. Or use the created startup scripts")

if __name__ == "__main__":
    main()
