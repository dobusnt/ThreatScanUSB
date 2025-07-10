#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Scanner Engine Module

This module handles the scanning of USB devices for potential threats,
including malware detection, autorun files, and suspicious files.
"""

import logging
import os
import time
import threading
import hashlib
import magic
import yara
import requests
from pathlib import Path
import psutil
import pyclamd
from tqdm import tqdm
import json
import re
import binascii
import struct
import io
import zipfile
import math
import base64
from config import get_app_data_dir, get_resource_path

logger = logging.getLogger('ThreatScanUsb.Scanner')

# Common malware hashes (MD5) - abbreviated list of well-known malware
KNOWN_MALICIOUS_HASHES = {
    '5b4d6b11d66ce242b3e8541e0b8c0139': 'Trojan.Win32.Generic',
    '7c53c24ac647577f8c097ff62cbe0125': 'Backdoor.Win32.Generic',
    'e70854fe53a64a91ed56992efde5a67b': 'Worm.Win32.Generic',
    'a8c5c0d39753c97e1ffdfc6b17423dd7': 'Ransomware.Generic',
    'ad8965f5e464a62bac6a297c454fbd3e': 'Spyware.Generic',
    'd41d8cd98f00b204e9800998ecf8427e': 'NotAVirus.EmptyFile'  # Empty file hash
}

# Suspicious APIs commonly used in malware
SUSPICIOUS_API_PATTERNS = [
    # Process manipulation
    r'CreateRemoteThread',
    r'WriteProcessMemory', 
    r'VirtualAllocEx',
    r'SetWindowsHook',
    r'WinExec',
    r'ShellExecute',
    
    # Registry manipulation
    r'RegCreateKey',
    r'RegSetValue',
    
    # System persistence
    r'CurrentVersion\\Run',
    r'Schedule(d)?Tasks',
    r'StartupItems',
    r'Win(dows)?Logon',
    
    # Networking
    r'WS2_32\.dll',
    r'WSASocket',
    r'InternetOpen',
    r'HttpSendRequest',
    r'InternetConnect',
    r'connect\(',
    r'recv\(',
    r'send\(',
    
    # Data theft
    r'GetClipboardData',
    r'keylog',
    r'SetWindowsHookEx',
    r'GetAsyncKeyState',
    r'GetKeyState',
    
    # Anti-debug/VM
    r'IsDebuggerPresent',
    r'CheckRemoteDebuggerPresent',
    r'GetTickCount',
    r'QueryPerformanceCounter',
    r'VirtualBox',
    r'VMware',
    r'QEMU',
    r'SbieDll\.dll',  # Sandboxie
    
    # Obfuscation
    r'VirtualProtect',
    r'LoadLibrary',
    r'GetProcAddress',
    
    # Command and control
    r'cmd\.exe',
    r'powershell',
    r'bitsadmin',
    r'certutil -urlcache',
    r'RegSvr32',
    
    # File operations
    r'CreateFile',
    r'WriteFile',
    r'CopyFile',
    r'MoveFile',
    r'DeleteFile',
    
    # Encryption/ransomware
    r'CryptEncrypt',
    r'CryptAcquireContext',
    r'CryptCreateHash',
    
    # Privilege escalation
    r'AdjustTokenPrivileges',
    r'SeDebugPrivilege'
]

# Suspicious strings found in malware
SUSPICIOUS_STRINGS = [
    # Common C2 domains and patterns
    r'\.onion',
    r'\.no-ip\.org',
    r'\.ddns\.',
    r'\.hopto\.',
    r'pastebin\.com',
    r'githubusercontent\.com',
    
    # Common malware strings
    r'botnet',
    r'backdoor',
    r'rootkit',
    r'keylogger',
    r'spyware',
    r'virus',
    r'trojan',
    r'malware',
    r'ransom',
    r'payload',
    r'inject',
    r'exploit',
    
    # Suspicious behaviors
    r'startup',
    r'autorun',
    r'auto-run',
    r'task.?scheduler',
    r'disable.?defender',
    r'disable.?firewall',
    r'disable.?update',
    r'bypass.?uac',
    r'dump.?password',
    r'steal.?data',
    r'collect.?info',
    r'screen.?capture',
    r'web.?camera',
    r'microphone',
    r'spread.?file',
    r'encrypt.?file',
    r'decrypt.?file',
    r'bitcoin',
    r'wallet',
    r'ransom',
    r'payment',
    r'miner',
    r'mining',
    r'monero',
    r'xmrig',
    
    # Obfuscation techniques
    r'base64_decode',
    r'base64_encode',
    r'eval\(',
    r'exec\(',
    r'fromCharCode',
    r'String\.fromCharCode',
    r'ShellExecute',
    r'hidden',
    
    # Command execution
    r'cmd\.exe',
    r'cmd /c ',
    r'cmd\.exe /c',
    r'powershell\.exe',
    r'powershell -e',
    r'wscript\.exe',
    r'cscript\.exe',
    r'bitsadmin',
    r'schtasks',
    r'rundll32',
    r'regsvr32'
]

# Base64-encoded commands and scripts
BASE64_PATTERN = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

# Unicode obfuscation pattern
UNICODE_OBFUSCATION = re.compile(r'(\\\w{4}){3,}')

# Suspicious script patterns
SCRIPT_PATTERNS = {
    # PowerShell patterns
    'powershell': [
        r'-ExecutionPolicy Bypass',
        r'-Exec Bypass',
        r'-EncodedCommand',
        r'-e ',
        r'-enc ',
        r'IEX\s?\(',
        r'Invoke-Expression',
        r'Invoke-WebRequest',
        r'Net\.WebClient',
        r'DownloadString',
        r'DownloadFile',
        r'Start-Process',
        r'New-Object',
        r'hidden',
        r'Invoke-Mimikatz',
        r'Invoke-Shellcode',
        r'WinRM',
        r'PSExec',
        r'Get-WmiObject',
        r'Set-WmiInstance',
        r'Get-Process',
        r'Add-MpPreference -ExclusionPath'
    ],
    
    # VBScript patterns
    'vbs': [
        r'CreateObject\s*\(\s*["\']WScript\.Shell["\']\s*\)',
        r'CreateObject\s*\(\s*["\']Scripting\.FileSystemObject["\']\s*\)',
        r'CreateObject\s*\(\s*["\']WScript\.Network["\']\s*\)',
        r'CreateObject\s*\(\s*["\']Shell\.Application["\']\s*\)',
        r'CreateObject\s*\(\s*["\']ADODB',
        r'CreateObject\s*\(\s*["\']Microsoft\.XMLHTTP["\']\s*\)',
        r'Run\s*\(',
        r'RegWrite',
        r'cmd\.exe'
    ],
    
    # Batch patterns
    'bat': [
        r'net user',
        r'net localgroup administrators',
        r'reg add',
        r'reg delete',
        r'taskkill /f',
        r'shutdown',
        r'attrib \+',
        r'sc config',
        r'netsh firewall',
        r'netsh advfirewall',
        r'ren ',
        r'del /f',
        r'rd /s /q',
        r'schtasks /create',
        r'bitsadmin /transfer',
        r'start /b',
        r'wmic'
    ],
    
    # JavaScript patterns
    'js': [
        r'eval\s*\(',
        r'unescape\s*\(',
        r'document\.write\s*\(',
        r'String\.fromCharCode',
        r'\\x[0-9A-Fa-f]{2}',
        r'ActiveXObject',
        r'WScript\.Shell',
        r'new Function\s*\(',
        r'WebSocket',
        r'XMLHttpRequest',
        r'fetch\s*\(',
        r'document\.createElement',
        r'iframe',
        r'atob\s*\(',
        r'btoa\s*\('
    ],
    
    # Python patterns
    'py': [
        r'subprocess\.Popen',
        r'subprocess\.call',
        r'os\.system',
        r'__import__\s*\(',
        r'exec\s*\(',
        r'eval\s*\(',
        r'compile\s*\(',
        r'pickle\.loads',
        r'marshal\.loads',
        r'base64\.b64decode',
        r'pyautogui',
        r'shutil\.copy',
        r'psutil',
        r'socket\.connect',
        r'requests\.get',
        r'urllib\.request',
        r'smtplib',
        r'ftplib'
    ]
}

class ScanResult:
    """Container for scan results."""
    
    def __init__(self, path, is_threat=False, threat_type=None, threat_name=None, confidence=0, details=None):
        self.path = path
        self.is_threat = is_threat
        self.threat_type = threat_type  # e.g., 'malware', 'suspicious', 'autorun'
        self.threat_name = threat_name  # specific name if identified
        self.confidence = confidence  # 0-100 confidence score
        self.details = details or {}  # Additional details
        self.scan_time = time.time()
    
    def __str__(self):
        if self.is_threat:
            return f"THREAT: {self.path} - {self.threat_type} ({self.threat_name}) - Confidence: {self.confidence}%"
        else:
            return f"CLEAN: {self.path}"


class ScanEngine:
    """Engine for scanning devices for threats."""
    
    # Suspicious file extensions and names
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1', 
        '.jar', '.pif', '.hta', '.com', '.msi', '.reg', '.py', '.vba',
        '.wsf', '.jse', '.vbe', '.wsh', '.sct', '.lnk', '.url', '.hm',
        '.php', '.asp', '.aspx', '.cpl', '.ocx', '.sys', '.bin', '.iso'
    }
    
    HIGHLY_SUSPICIOUS_EXTENSIONS = {
        '.pif', '.scr', '.hta', '.jse', '.vbe', '.wsh', '.sct', '.ocx'
    }
    
    AUTORUN_FILES = {
        'autorun.inf', 'desktop.ini', 'autorun.exe', 'thumbs.db', 
        'startup.bat', 'startup.vbs', 'setup.exe', 'install.exe'
    }
    
    # Archive file extensions
    ARCHIVE_EXTENSIONS = {
        '.zip', '.rar', '.7z', '.tar', '.gz', '.gzip', '.tgz', '.jar', '.cab'
    }
    
    def __init__(self, config):
        """
        Initialize the scanner engine.
        
        Args:
            config: Configuration dictionary with scanning options
        """
        self.config = config
        self.scan_in_progress = False
        self.current_scan_path = None
        self.scan_results = []
        self.scan_thread = None
        self.stop_scan_event = threading.Event()
        self.scan_progress = {'total_files': 0, 'scanned_files': 0, 'percent_complete': 0}
        
        # Initialize virus scanning components if available
        self.clamd = None
        if self.config.get('use_clamav', False):
            try:
                self.clamd = pyclamd.ClamdAgnostic()
                self.clamd.ping()
                logger.info("ClamAV daemon connected successfully")
            except Exception as e:
                logger.warning(f"ClamAV daemon not available: {e}")
                self.clamd = None
        
        # Initialize YARA rules if available
        self.yara_rules = None
        if self.config.get('use_yara', True):
            try:
                # Get YARA rules path from configuration or use default
                yara_rules_path = self.config.get('yara_rules_path')
                if not yara_rules_path:
                    yara_rules_path = get_resource_path('yara_rules')
                
                yara_path = Path(yara_rules_path)
                if yara_path.exists():
                    rule_files = list(yara_path.glob('*.yar')) + list(yara_path.glob('*.yara'))
                    if rule_files:
                        self.yara_rules = yara.compile(filepaths={
                            f.stem: str(f) for f in rule_files
                        })
                        logger.info(f"YARA rules loaded from {yara_rules_path}: {len(rule_files)} files")
                    else:
                        logger.warning(f"No YARA rules found in {yara_rules_path}")
                else:
                    logger.warning(f"YARA rules directory not found: {yara_rules_path}")
            except Exception as e:
                logger.error(f"Error loading YARA rules: {e}", exc_info=True)
        
        # VirusTotal API key
        self.vt_api_key = self.config.get('virustotal_api_key')
        if self.vt_api_key:
            logger.info("VirusTotal API integration available")
    
    def scan_device(self, drive_path):
        """Start scanning a USB device."""
        if self.scan_in_progress:
            logger.warning(f"Scan already in progress for {self.current_scan_path}")
            return False
        
        self.scan_in_progress = True
        self.current_scan_path = drive_path
        self.scan_results = []
        self.stop_scan_event.clear()
        
        # Start scan in a new thread
        self.scan_thread = threading.Thread(
            target=self._scan_thread, 
            args=(drive_path,), 
            daemon=True
        )
        self.scan_thread.start()
        
        logger.info(f"Started scan of device: {drive_path}")
        return True
    
    def scan_directory(self, directory_path):
        """Start scanning a specific directory."""
        if self.scan_in_progress:
            logger.warning(f"Scan already in progress for {self.current_scan_path}")
            return False
        
        if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
            logger.error(f"Invalid directory path: {directory_path}")
            return False
            
        self.scan_in_progress = True
        self.current_scan_path = directory_path
        self.scan_results = []
        self.stop_scan_event.clear()
        
        # Start scan in a new thread
        self.scan_thread = threading.Thread(
            target=self._scan_thread, 
            args=(directory_path,), 
            daemon=True
        )
        self.scan_thread.start()
        
        logger.info(f"Started scan of directory: {directory_path}")
        return True
    
    def stop_scan(self):
        """Stop the current scan."""
        if self.scan_in_progress and self.scan_thread and self.scan_thread.is_alive():
            logger.info("Stopping current scan...")
            self.stop_scan_event.set()
            self.scan_thread.join(timeout=3.0)
            logger.info("Scan stopped")
            self.scan_in_progress = False
            return True
        return False
    
    def _scan_thread(self, path):
        """Run the scan in a separate thread."""
        try:
            logger.info(f"Starting scan of {path}")
            
            # Collect all file paths
            start_time = time.time()
            all_files = []
            try:
                for root, dirs, files in os.walk(path):
                    # Skip hidden directories if configured
                    if self.config.get('skip_hidden_dirs', True):
                        dirs[:] = [d for d in dirs if not d.startswith('.') and not os.path.islink(os.path.join(root, d))]
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        all_files.append(file_path)
                        
                        # Check if we should stop
                        if self.stop_scan_event.is_set():
                            logger.info("Scan cancelled during file enumeration")
                            self.scan_in_progress = False
                            return
            except Exception as e:
                logger.error(f"Error enumerating files on {path}: {e}", exc_info=True)
            
            self.scan_progress['total_files'] = len(all_files)
            logger.info(f"Found {len(all_files)} files to scan on {path}")
            
            # Process each file
            for i, file_path in enumerate(tqdm(all_files, desc=f"Scanning {path}")):
                result = self._scan_file(file_path)
                if result:
                    self.scan_results.append(result)
                
                # Update progress
                self.scan_progress['scanned_files'] = i + 1
                self.scan_progress['percent_complete'] = int((i + 1) / max(1, len(all_files)) * 100)
                
                # Check if we should stop
                if self.stop_scan_event.is_set():
                    logger.info("Scan cancelled during file scanning")
                    break
            
            scan_duration = time.time() - start_time
            threats_found = sum(1 for r in self.scan_results if r.is_threat)
            
            logger.info(f"Scan of {path} completed in {scan_duration:.1f} seconds")
            logger.info(f"Scan results: {len(all_files)} files scanned, {threats_found} threats found")
            
            # Save scan results
            self._save_scan_results(path, scan_duration, threats_found, len(all_files))
            
        except Exception as e:
            logger.error(f"Error during scan of {path}: {e}", exc_info=True)
        finally:
            self.scan_in_progress = False
    
    def _scan_file(self, file_path):
        """
        Scan a single file for threats using multiple detection techniques.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            ScanResult object if a threat is found, None otherwise
        """
        try:
            # Skip if file doesn't exist or is too large
            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                return None
                
            file_size = os.path.getsize(file_path)
            max_size = self.config.get('max_file_size_mb', 100) * 1024 * 1024
            
            if file_size > max_size:
                logger.info(f"Skipping large file: {file_path} ({file_size/1024/1024:.1f} MB)")
                return None
            
            # Get basic file information
            file_name = os.path.basename(file_path)
            file_ext = os.path.splitext(file_name)[1].lower()
            
            # Initialize score system (0-100)
            threat_score = 0
            detection_details = {}
            
            # 1. Check for autorun and system files
            if file_name.lower() in self.AUTORUN_FILES:
                threat_score += 30
                detection_details["autorun_file"] = True
            
            # 2. Check file extension
            if file_ext in self.HIGHLY_SUSPICIOUS_EXTENSIONS:
                threat_score += 25
                detection_details["highly_suspicious_extension"] = True
            elif file_ext in self.SUSPICIOUS_EXTENSIONS:
                threat_score += 10
                detection_details["suspicious_extension"] = True
            
            # 3. Check for hidden files
            is_hidden = False
            try:
                # On Windows
                if os.name == 'nt':
                    import win32api, win32con
                    attrs = win32api.GetFileAttributes(file_path)
                    is_hidden = bool(attrs & win32con.FILE_ATTRIBUTE_HIDDEN)
                else:
                    # On Unix-like systems
                    is_hidden = os.path.basename(file_path).startswith('.')
            except:
                # Fallback if attribute check fails
                is_hidden = os.path.basename(file_path).startswith('.')
                
            if is_hidden:
                if file_ext in self.SUSPICIOUS_EXTENSIONS:
                    threat_score += 30
                    detection_details["hidden_suspicious_file"] = True
                else:
                    threat_score += 10
                    detection_details["hidden_file"] = True
            
            # 4. Calculate file hash and check against known malware hashes
            try:
                md5_hash = ""
                with open(file_path, "rb") as f:
                    md5_hash = hashlib.md5(f.read()).hexdigest()
                
                if md5_hash in KNOWN_MALICIOUS_HASHES:
                    threat_score = 100  # Known malware
                    detection_details["known_malware"] = KNOWN_MALICIOUS_HASHES[md5_hash]
            except Exception as e:
                logger.debug(f"Error calculating hash for {file_path}: {e}")
            
            # 5. Check file type using magic
            try:
                file_type = magic.from_file(file_path)
                mime_type = magic.from_file(file_path, mime=True)
                
                detection_details["file_type"] = file_type
                detection_details["mime_type"] = mime_type
                
                # Check for extension mismatches
                if file_ext != "":
                    # Executable with wrong extension
                    if "executable" in file_type.lower() and file_ext not in (".exe", ".dll", ".sys", ".ocx", ".com"):
                        threat_score += 50
                        detection_details["extension_mismatch"] = f"File is executable but has {file_ext} extension"
                    
                    # Script file with wrong extension
                    elif "script" in file_type.lower() and file_ext not in (".ps1", ".vbs", ".js", ".py", ".bat", ".cmd"):
                        threat_score += 40
                        detection_details["extension_mismatch"] = f"File is script but has {file_ext} extension"
                    
                    # Archive with wrong extension
                    elif "archive" in file_type.lower() and file_ext not in self.ARCHIVE_EXTENSIONS:
                        threat_score += 30
                        detection_details["extension_mismatch"] = f"File is archive but has {file_ext} extension"
            except Exception as e:
                logger.debug(f"Error getting file type for {file_path}: {e}")
            
            # 6. Analyze file content for suspicious patterns
            try:
                is_binary = False
                file_content = ""
                suspicious_patterns_found = []
                
                with open(file_path, 'rb') as f:
                    # Read first 64KB for analysis
                    data = f.read(65536)
                    
                    # Check if file is binary
                    try:
                        file_content = data.decode('utf-8', errors='strict')
                        is_binary = False
                    except UnicodeDecodeError:
                        is_binary = True
                        
                # 6.1 Analyze text files
                if not is_binary:
                    # Check for suspicious script patterns
                    script_type = None
                    if file_ext == '.ps1':
                        script_type = 'powershell'
                    elif file_ext == '.vbs':
                        script_type = 'vbs'
                    elif file_ext == '.bat' or file_ext == '.cmd':
                        script_type = 'bat'
                    elif file_ext == '.js':
                        script_type = 'js'
                    elif file_ext == '.py':
                        script_type = 'py'
                    
                    # If we identified the script type, check for suspicious patterns
                    if script_type and script_type in SCRIPT_PATTERNS:
                        patterns = SCRIPT_PATTERNS[script_type]
                        for pattern in patterns:
                            if re.search(pattern, file_content, re.IGNORECASE):
                                suspicious_patterns_found.append(pattern)
                    
                    # Check for suspicious strings in any text file
                    for pattern in SUSPICIOUS_STRINGS:
                        if re.search(pattern, file_content, re.IGNORECASE):
                            suspicious_patterns_found.append(pattern)
                    
                    # Check for base64 encoded content which might be obfuscated commands
                    base64_matches = BASE64_PATTERN.findall(file_content)
                    if base64_matches:
                        # Look through some of the matches (not all to avoid performance issues)
                        for match in base64_matches[:5]:
                            if len(match) > 20:  # Only check longer strings
                                try:
                                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                                    # Check if decoded content has suspicious commands
                                    for pattern in SUSPICIOUS_STRINGS:
                                        if re.search(pattern, decoded, re.IGNORECASE):
                                            suspicious_patterns_found.append(f"base64:{pattern}")
                                            break
                                except:
                                    pass  # Not valid base64 or other decode error
                    
                    # Check for Unicode obfuscation
                    if UNICODE_OBFUSCATION.search(file_content):
                        suspicious_patterns_found.append("unicode_obfuscation")
                
                # 6.2 Analyze binary files
                else:
                    # For binary files, search for text strings that could indicate malicious functionality
                    # Extract all printable strings (4+ chars)
                    try:
                        strings_data = ""
                        current_string = ""
                        for byte in data:
                            char = chr(byte)
                            if 32 <= byte <= 126:  # Printable ASCII
                                current_string += char
                            else:
                                if len(current_string) >= 4:
                                    strings_data += current_string + "\n"
                                current_string = ""
                        
                        # Add the last string if it's long enough
                        if len(current_string) >= 4:
                            strings_data += current_string
                        
                        # Look for suspicious API calls in the strings data
                        for pattern in SUSPICIOUS_API_PATTERNS:
                            if re.search(pattern, strings_data, re.IGNORECASE):
                                suspicious_patterns_found.append(pattern)
                        
                        # Look for suspicious strings in the strings data
                        for pattern in SUSPICIOUS_STRINGS:
                            if re.search(pattern, strings_data, re.IGNORECASE):
                                suspicious_patterns_found.append(pattern)
                    except Exception as e:
                        logger.debug(f"Error extracting strings from {file_path}: {e}")
                
                # Add to threat score based on suspicious patterns
                if suspicious_patterns_found:
                    pattern_score = min(60, len(suspicious_patterns_found) * 5)  # Cap at 60
                    threat_score += pattern_score
                    detection_details["suspicious_patterns"] = suspicious_patterns_found
            except Exception as e:
                logger.debug(f"Error analyzing content of {file_path}: {e}")
                
            # 7. Calculate file entropy (randomness - high entropy can indicate encryption or packing)
            try:
                if os.path.exists(file_path) and file_size > 0 and file_size <= max_size:
                    entropy = self._calculate_file_entropy(file_path)
                    
                    # Extremely high entropy (> 7.8) is suspicious, especially for certain file types
                    if entropy > 7.8:
                        if file_ext in self.SUSPICIOUS_EXTENSIONS:
                            threat_score += 30
                        else:
                            threat_score += 15
                        detection_details["high_entropy"] = entropy
            except Exception as e:
                logger.debug(f"Error calculating entropy for {file_path}: {e}")
            
            # 8. PE file analysis for executables
            if file_ext in ('.exe', '.dll', '.sys', '.scr', '.ocx') or 'executable' in detection_details.get("file_type", "").lower():
                try:
                    pe_anomalies = self._analyze_pe_file(file_path)
                    if pe_anomalies:
                        # Add to threat score based on PE anomalies
                        pe_score = min(50, len(pe_anomalies) * 10)
                        threat_score += pe_score
                        detection_details["pe_anomalies"] = pe_anomalies
                except Exception as e:
                    logger.debug(f"Error analyzing PE file {file_path}: {e}")
            
            # 9. Archive file scanning
            if file_ext in self.ARCHIVE_EXTENSIONS:
                try:
                    archive_threats = self._scan_archive(file_path)
                    if archive_threats:
                        threat_score += 40
                        detection_details["archive_threats"] = archive_threats
                except Exception as e:
                    logger.debug(f"Error scanning archive {file_path}: {e}")
            
            # 10. YARA rules scan
            if self.yara_rules:
                try:
                    matches = self.yara_rules.match(file_path)
                    if matches:
                        # YARA match is a strong indicator
                        threat_score += 70
                        detection_details["yara_matches"] = [m.rule for m in matches]
                except Exception as e:
                    logger.debug(f"YARA scan error for {file_path}: {e}")
            
            # 11. ClamAV scan if available
            if self.clamd:
                try:
                    scan_result = self.clamd.scan_file(file_path)
                    if scan_result and file_path in scan_result:
                        status = scan_result[file_path][0]
                        if status == 'FOUND':
                            threat_name = scan_result[file_path][1]
                            threat_score = 100  # ClamAV detection is definitive
                            detection_details["clamav_detection"] = threat_name
                except Exception as e:
                    logger.debug(f"ClamAV scan error for {file_path}: {e}")
            
            # 12. VirusTotal check for suspicious files
            if (self.vt_api_key and file_ext in self.SUSPICIOUS_EXTENSIONS and 
                    self.config.get('use_virustotal', False)):
                try:
                    vt_result = self._check_virustotal(file_path)
                    if vt_result and vt_result.get('positives', 0) > 0:
                        vt_score = min(vt_result.get('positives', 0) * 5, 80)
                        threat_score += vt_score
                        detection_details["virustotal"] = {
                            'positives': vt_result.get('positives'),
                            'total': vt_result.get('total'),
                            'permalink': vt_result.get('permalink')
                        }
                except Exception as e:
                    logger.debug(f"VirusTotal check error for {file_path}: {e}")
            
            # Determine final threat status
            is_threat = False
            threat_type = None
            threat_name = None
            
            # Set custom confidence thresholds by file type
            threat_threshold = 50  # Default threshold
            
            # For certain file types, lower the threshold
            if file_ext in self.HIGHLY_SUSPICIOUS_EXTENSIONS:
                threat_threshold = 30
            elif file_ext in self.SUSPICIOUS_EXTENSIONS:
                threat_threshold = 40
            
            # Make the final determination
            if threat_score >= threat_threshold:
                is_threat = True
                
                # Determine threat type and name
                if "known_malware" in detection_details:
                    threat_type = "malware"
                    threat_name = detection_details["known_malware"]
                elif "clamav_detection" in detection_details:
                    threat_type = "malware"
                    threat_name = detection_details["clamav_detection"]
                elif "yara_matches" in detection_details:
                    threat_type = "suspicious"
                    threat_name = f"YARA: {detection_details['yara_matches'][0]}"
                elif "virustotal" in detection_details:
                    threat_type = "suspicious"
                    threat_name = f"VirusTotal: {detection_details['virustotal']['positives']} detections"
                elif "pe_anomalies" in detection_details:
                    threat_type = "suspicious"
                    threat_name = f"Suspicious executable: {detection_details['pe_anomalies'][0]}"
                elif "extension_mismatch" in detection_details:
                    threat_type = "suspicious"
                    threat_name = f"Extension mismatch: {detection_details['extension_mismatch']}"
                elif "suspicious_patterns" in detection_details:
                    threat_type = "suspicious"
                    threat_name = f"Suspicious pattern: {detection_details['suspicious_patterns'][0]}"
                elif "hidden_suspicious_file" in detection_details:
                    threat_type = "suspicious"
                    threat_name = "Hidden suspicious file"
                elif "archive_threats" in detection_details:
                    threat_type = "suspicious"
                    threat_name = f"Archive containing suspicious files"
                elif "autorun_file" in detection_details:
                    threat_type = "autorun"
                    threat_name = f"Autorun file: {file_name}"
                else:
                    threat_type = "suspicious"
                    threat_name = "Multiple suspicious indicators"
                
                # Create and return the scan result
                return ScanResult(
                    file_path,
                    is_threat=is_threat,
                    threat_type=threat_type,
                    threat_name=threat_name,
                    confidence=threat_score,
                    details=detection_details
                )
            
            # No threats found
            return None
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return None
    
    def _calculate_file_entropy(self, file_path):
        """
        Calculate Shannon entropy for a file. High entropy can indicate encryption or packing.
        
        Args:
            file_path: Path to the file
            
        Returns:
            float: Entropy value between 0 and 8 (8 is maximum entropy)
        """
        try:
            byte_counts = [0] * 256
            total_bytes = 0
            
            # Read the file in chunks
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    
                    # Count bytes
                    for byte in chunk:
                        byte_counts[byte] += 1
                        total_bytes += 1
            
            # Calculate entropy
            entropy = 0
            for count in byte_counts:
                if count > 0:
                    probability = count / total_bytes
                    entropy -= probability * math.log2(probability)
            
            return entropy
        except Exception as e:
            logger.debug(f"Error calculating entropy: {e}")
            return 0
    
    def _analyze_pe_file(self, file_path):
        """
        Analyze PE file structure for anomalies that could indicate malicious intent.
        
        Args:
            file_path: Path to the PE file
            
        Returns:
            list: List of anomalies found
        """
        anomalies = []
        
        try:
            # Basic PE header checks
            with open(file_path, 'rb') as f:
                data = f.read(2)
                if data != b'MZ':
                    anomalies.append("invalid_mz_header")
                    return anomalies  # Not a valid PE file
                
                # Additional checks could be added here with a full PE parser library
                # This is a simplified version that looks for common indicators
                
                # Look for signs of packing or obfuscation
                f.seek(0)
                full_data = f.read()
                
                # Check for common packer signatures
                packers = {
                    b"UPX": "UPX_packer",
                    b"PEC2": "PECompact_packer",
                    b"PEtite": "PEtite_packer",
                    b"MPRESS": "MPRESS_packer",
                    b"ASPack": "ASPack_packer",
                    b"FSG": "FSG_packer",
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xEE\x00\x00\x00": "Themida_packer"
                }
                
                for signature, name in packers.items():
                    if signature in full_data:
                        anomalies.append(name)
                
                # Check section names for suspicious ones
                section_names = [b".text", b".data", b".rdata", b".bss", b".rsrc", b".idata", b".edata", b".pdata"]
                uncommon_sections = False
                
                # Basic section table search
                pos = full_data.find(b".text")
                if pos > 0:
                    # Assume we found the section table
                    for i in range(pos, len(full_data) - 8, 40):  # Typical section entry size
                        found = False
                        for name in section_names:
                            if full_data[i:i+len(name)] == name:
                                found = True
                                break
                        if not found and not full_data[i:i+8].isspace() and all(c < 127 and c > 31 for c in full_data[i:i+8]):
                            uncommon_sections = True
                            break
                
                if uncommon_sections:
                    anomalies.append("uncommon_section_names")
        
        except Exception as e:
            logger.debug(f"Error analyzing PE file: {e}")
        
        return anomalies
    
    def _scan_archive(self, file_path):
        """
        Scan archive files for suspicious content.
        
        Args:
            file_path: Path to the archive file
            
        Returns:
            list: List of suspicious files found in the archive
        """
        suspicious_files = []
        
        try:
            if file_path.lower().endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    # Scan file list for suspicious files
                    for file_info in zip_ref.infolist():
                        file_name = file_info.filename
                        file_ext = os.path.splitext(file_name)[1].lower()
                        
                        # Check for suspicious extensions
                        if file_ext in self.SUSPICIOUS_EXTENSIONS:
                            suspicious_files.append(f"{file_name} (suspicious extension)")
                        
                        # Check for autorun files
                        if os.path.basename(file_name).lower() in self.AUTORUN_FILES:
                            suspicious_files.append(f"{file_name} (autorun file)")
                        
                        # Check for hidden files
                        if '/..' in file_name or file_name.startswith('.'):
                            suspicious_files.append(f"{file_name} (hidden file)")
                        
                        # Check for abnormally high compression ratio (potential indicator of obfuscation)
                        if file_info.file_size > 0:
                            compression_ratio = file_info.compress_size / file_info.file_size
                            if compression_ratio < 0.1 and file_info.file_size > 1000:
                                suspicious_files.append(f"{file_name} (abnormal compression)")
        except Exception as e:
            logger.debug(f"Error scanning archive: {e}")
        
        return suspicious_files
    
    def _check_virustotal(self, file_path):
        """Check a file hash against VirusTotal."""
        try:
            # Calculate file hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Query VirusTotal API
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            params = {'apikey': self.vt_api_key, 'resource': file_hash}
            response = requests.get(url, params=params)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('response_code') == 1:  # Found in VT database
                    return result
            
            return None
        except Exception as e:
            logger.error(f"Error checking VirusTotal for {file_path}: {e}")
            return None
    
    def quarantine_file(self, file_path, move_to=None):
        """
        Move a suspicious file to quarantine.
        
        Args:
            file_path: Path to file to quarantine
            move_to: Quarantine directory (default: config or app_data/quarantine)
        """
        try:
            if not os.path.exists(file_path):
                logger.error(f"Cannot quarantine file {file_path}: File does not exist")
                return False
            
            # Determine quarantine location
            if move_to is None:
                move_to = self.config.get('quarantine_dir')
                if not move_to:
                    # Use the application data directory
                    app_data_dir = get_app_data_dir()
                    move_to = os.path.join(app_data_dir, 'quarantine')
            
            # Ensure quarantine directory exists
            os.makedirs(move_to, exist_ok=True)
            
            # Generate a unique filename for the quarantined file
            file_name = os.path.basename(file_path)
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            quarantine_name = f"{timestamp}_{file_name}"
            quarantine_path = os.path.join(move_to, quarantine_name)
            
            # Move file to quarantine
            os.rename(file_path, quarantine_path)
            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            
            return True
        except Exception as e:
            logger.error(f"Error quarantining file {file_path}: {e}", exc_info=True)
            return False
    
    def _save_scan_results(self, path, duration, threats_found, total_files):
        """Save scan results to a file."""
        try:
            # Create results directory in app data
            app_data_dir = get_app_data_dir()
            results_dir = os.path.join(app_data_dir, 'scan_results')
            os.makedirs(results_dir, exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            result_file = os.path.join(results_dir, f"scan_{timestamp}.json")
            
            # Create result data
            result_data = {
                'scan_time': timestamp,
                'scan_path': path,
                'scan_duration_seconds': duration,
                'total_files_scanned': total_files,
                'threats_found': threats_found,
                'results': []
            }
            
            # Add individual threat results
            for result in self.scan_results:
                if result.is_threat:
                    result_data['results'].append({
                        'path': result.path,
                        'threat_type': result.threat_type,
                        'threat_name': result.threat_name,
                        'confidence': result.confidence,
                        'details': result.details
                    })
            
            # Save to file
            with open(result_file, 'w') as f:
                json.dump(result_data, f, indent=4)
                
            logger.info(f"Scan results saved to {result_file}")
            return result_file
            
        except Exception as e:
            logger.error(f"Error saving scan results: {e}", exc_info=True)
            return None
            
    def get_scan_progress(self):
        """Get current scan progress information."""
        if not self.scan_in_progress:
            return {
                'status': 'idle',
                'drive': None,
                'progress': 100,
                'threats_found': len([r for r in self.scan_results if r.is_threat])
            }
        
        return {
            'status': 'scanning',
            'drive': self.current_scan_path,
            'progress': self.scan_progress.get('percent_complete', 0),
            'threats_found': len([r for r in self.scan_results if r.is_threat]),
            'files_scanned': self.scan_progress.get('scanned_files', 0),
            'total_files': self.scan_progress.get('total_files', 0)
        }
    
    def get_scan_results(self):
        """Get the results of the most recent scan."""
        return self.scan_results 