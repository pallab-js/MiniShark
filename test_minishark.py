#!/usr/bin/env python3
"""
Test script for MiniShark
This script tests basic functionality without requiring root privileges
"""

import sys
import os
import subprocess
import time

def test_imports():
    """Test if all required modules can be imported"""
    print("Testing imports...")
    try:
        import scapy
        from colorama import init, Fore, Back, Style
        from tabulate import tabulate
        print("✓ All imports successful")
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def test_help():
    """Test if the help option works"""
    print("Testing help option...")
    try:
        result = subprocess.run([sys.executable, 'minishark.py', '--help'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and 'MiniShark' in result.stdout:
            print("✓ Help option works")
            return True
        else:
            print("✗ Help option failed")
            return False
    except Exception as e:
        print(f"✗ Help test error: {e}")
        return False

def test_interfaces():
    """Test interface listing"""
    print("Testing interface listing...")
    try:
        result = subprocess.run([sys.executable, 'minishark.py', '--interfaces'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and 'Available Network Interfaces' in result.stdout:
            print("✓ Interface listing works")
            return True
        else:
            print("✗ Interface listing failed")
            return False
    except Exception as e:
        print(f"✗ Interface test error: {e}")
        return False

def test_syntax():
    """Test Python syntax"""
    print("Testing Python syntax...")
    try:
        result = subprocess.run([sys.executable, '-m', 'py_compile', 'minishark.py'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✓ Syntax check passed")
            return True
        else:
            print(f"✗ Syntax error: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Syntax test error: {e}")
        return False

def main():
    """Run all tests"""
    print("MiniShark Test Suite")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_syntax,
        test_help,
        test_interfaces
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("✓ All tests passed! MiniShark is ready to use.")
        print("\nNote: Packet capture requires root/administrator privileges.")
        print("Run with: sudo python minishark.py (Linux/macOS)")
        print("Or: Run Command Prompt as Administrator (Windows)")
    else:
        print("✗ Some tests failed. Please check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main()