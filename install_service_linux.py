#!/usr/bin/env python3
"""
Linux systemd Service Installation Script for Memory Shellcode Detection Framework
"""

import os
import sys
import subprocess
from pathlib import Path

def create_systemd_service():
    """Create systemd service for Linux"""
    print("🛠️ Creating systemd Service for Memory Shellcode Detection")
    print("=" * 60)
    
    # Get current directory
    current_dir = Path(__file__).parent.absolute()
    python_exe = sys.executable
    orchestrator_path = current_dir / "detection" / "orchestrator.py"
    
    # Service configuration
    service_name = "memory-shellcode-detection"
    service_content = f"""[Unit]
Description=Memory Shellcode Detection Framework
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={current_dir}
ExecStart={python_exe} {orchestrator_path}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    
    # Write service file
    service_file = f"/etc/systemd/system/{service_name}.service"
    
    try:
        with open(service_file, 'w') as f:
            f.write(service_content)
        print(f"✅ Service file created: {service_file}")
        
        # Reload systemd
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        print("✅ Systemd daemon reloaded")
        
        # Enable service
        subprocess.run(["systemctl", "enable", service_name], check=True)
        print("✅ Service enabled for auto-start")
        
        # Start service
        subprocess.run(["systemctl", "start", service_name], check=True)
        print("✅ Service started successfully!")
        
        print(f"\n📋 Service Information:")
        print(f"   Name: {service_name}")
        print(f"   Status: Installed and running")
        print(f"   Auto Start: Enabled")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to configure service: {e}")
        return False
    except Exception as e:
        print(f"❌ Error creating service: {e}")
        return False
    
    return True

def remove_systemd_service():
    """Remove systemd service"""
    print("🗑️ Removing systemd Service")
    print("=" * 60)
    
    service_name = "memory-shellcode-detection"
    
    try:
        # Stop the service
        subprocess.run(["systemctl", "stop", service_name], check=True)
        
        # Disable service
        subprocess.run(["systemctl", "disable", service_name], check=True)
        
        # Remove service file
        service_file = f"/etc/systemd/system/{service_name}.service"
        os.remove(service_file)
        
        # Reload systemd
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        
        print("✅ Service removed successfully!")
        
    except Exception as e:
        print(f"❌ Error removing service: {e}")

def create_startup_script():
    """Create startup script for manual installation"""
    print("📝 Creating Startup Script")
    print("=" * 60)
    
    current_dir = Path(__file__).parent.absolute()
    python_exe = sys.executable
    orchestrator_path = current_dir / "detection" / "orchestrator.py"
    
    # Create shell script for manual startup
    shell_content = f"""#!/bin/bash
echo "Starting Memory Shellcode Detection Framework..."
cd "{current_dir}"
"{python_exe}" "{orchestrator_path}"
"""
    
    shell_path = current_dir / "start_detection.sh"
    
    try:
        with open(shell_path, 'w') as f:
            f.write(shell_content)
        
        # Make executable
        os.chmod(shell_path, 0o755)
        print(f"✅ Startup script created: {shell_path}")
        
    except Exception as e:
        print(f"❌ Error creating startup script: {e}")

def main():
    """Main function"""
    print("🛡️ Memory Shellcode Detection Framework - Linux Service Installation")
    print("=" * 70)
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "remove":
            remove_systemd_service()
        elif sys.argv[1] == "startup":
            create_startup_script()
        else:
            print("Usage: python install_service.py [remove|startup]")
    else:
        # Check if running as root
        if os.geteuid() != 0:
            print("⚠️ Warning: This script should be run as root")
            print("   Use 'sudo python install_service.py' for full service installation")
            print("\n📝 Creating startup scripts instead...")
            create_startup_script()
        else:
            print("✅ Running as root - proceeding with service installation")
            if create_systemd_service():
                create_startup_script()
    
    print("\n🎉 Service installation completed!")
    print("\n📋 Next Steps:")
    print("   1. Service is now installed and configured")
    print("   2. Use 'systemctl start memory-shellcode-detection' to start")
    print("   3. Use 'systemctl stop memory-shellcode-detection' to stop")
    print("   4. Or use the created startup scripts")

if __name__ == "__main__":
    main()
