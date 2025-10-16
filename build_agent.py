#!/usr/bin/env python3
"""
Build script for the C agent core
Compiles agent_core.c for different platforms
"""

import os
import sys
import subprocess
import platform

def build_windows():
    """Build agent_core.c for Windows"""
    print("Building for Windows...")
    
    # Check if Visual Studio compiler is available
    try:
        result = subprocess.run(['cl'], capture_output=True, text=True)
        if result.returncode != 0:
            print("Visual Studio compiler not found. Please install Visual Studio Build Tools.")
            return False
    except FileNotFoundError:
        print("Visual Studio compiler not found. Please install Visual Studio Build Tools.")
        return False
    
    # Build command for Windows
    cmd = [
        'cl', '/LD', '/Fe:agent_core.dll',
        'agent/monitor/agent_core.c',
        '/I.', '/D_WIN32'
    ]
    
    try:
        result = subprocess.run(cmd, cwd=os.getcwd(), check=True)
        print("Windows build successful!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Windows build failed: {e}")
        return False

def build_linux():
    """Build agent_core.c for Linux"""
    print("Building for Linux...")
    
    # Check if gcc is available
    try:
        result = subprocess.run(['gcc', '--version'], capture_output=True, text=True)
        if result.returncode != 0:
            print("GCC not found. Please install gcc.")
            return False
    except FileNotFoundError:
        print("GCC not found. Please install gcc.")
        return False
    
    # Build command for Linux
    cmd = [
        'gcc', '-shared', '-fPIC', '-o', 'libagentcore.so',
        'agent/monitor/agent_core.c',
        '-I.'
    ]
    
    try:
        result = subprocess.run(cmd, cwd=os.getcwd(), check=True)
        print("Linux build successful!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Linux build failed: {e}")
        return False

def build_macos():
    """Build agent_core.c for macOS"""
    print("Building for macOS...")
    
    # Check if clang is available
    try:
        result = subprocess.run(['clang', '--version'], capture_output=True, text=True)
        if result.returncode != 0:
            print("Clang not found. Please install Xcode Command Line Tools.")
            return False
    except FileNotFoundError:
        print("Clang not found. Please install Xcode Command Line Tools.")
        return False
    
    # Build command for macOS
    cmd = [
        'clang', '-shared', '-fPIC', '-o', 'libagentcore.dylib',
        'agent/monitor/agent_core.c',
        '-I.'
    ]
    
    try:
        result = subprocess.run(cmd, cwd=os.getcwd(), check=True)
        print("macOS build successful!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"macOS build failed: {e}")
        return False

def main():
    """Main build function"""
    print("Memory Shellcode Detection Framework - Agent Build Script")
    print("=" * 60)
    
    # Detect platform
    system = platform.system().lower()
    print(f"Detected platform: {system}")
    
    # Create build directory
    build_dir = "build"
    os.makedirs(build_dir, exist_ok=True)
    
    # Change to build directory
    original_dir = os.getcwd()
    os.chdir(build_dir)
    
    try:
        # Build based on platform
        if system == "windows":
            success = build_windows()
        elif system == "linux":
            success = build_linux()
        elif system == "darwin":
            success = build_macos()
        else:
            print(f"Unsupported platform: {system}")
            return False
        
        if success:
            print("\nBuild completed successfully!")
            print("Agent core library is ready for use.")
            
            # List generated files
            print("\nGenerated files:")
            for file in os.listdir('.'):
                if file.endswith(('.dll', '.so', '.dylib')):
                    print(f"  - {file}")
            
            return True
        else:
            print("\nBuild failed!")
            return False
            
    finally:
        # Return to original directory
        os.chdir(original_dir)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
