#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Configuration Module

This module handles loading, saving, and managing application configuration.
"""

import os
import json
import logging
from pathlib import Path

logger = logging.getLogger('ThreatScanUsb.Config')

# Default configuration
DEFAULT_CONFIG = {
    # Scanner settings
    'max_file_size_mb': 100,  # Skip files larger than this size
    'skip_hidden_dirs': True,  # Skip hidden directories during scan
    'scan_executable_files_only': False,  # If True, only scan files with suspicious extensions
    
    # Scan components
    'use_yara': True,  # Use YARA rules for scanning
    'use_clamav': False,  # Use ClamAV for scanning
    'use_virustotal': False,  # Use VirusTotal API for checking suspicious files
    
    # Integration settings
    'virustotal_api_key': '',  # VirusTotal API key
    
    # File paths
    'yara_rules_path': 'resources/yara_rules',  # Path to YARA rules
    'quarantine_dir': '',  # Custom quarantine directory
    
    # UI settings
    'auto_scan_usb': True,  # Automatically scan USB devices when connected
    'notify_threats': True,  # Show notifications when threats are found
    'theme': 'system',  # UI theme (system, light, dark)
    
    # Advanced
    'debug_mode': False,  # Enable debug logging
}

# Global variables
APP_DIRECTORY = None  # Will be set at runtime

def set_app_directory(directory):
    """Set the application directory globally."""
    global APP_DIRECTORY
    APP_DIRECTORY = directory
    logger.info(f"Application directory set to: {APP_DIRECTORY}")

def get_config_path():
    """Get the path to the configuration file."""
    global APP_DIRECTORY
    
    # If running from a USB or non-standard location, prefer config in the app directory
    if APP_DIRECTORY:
        usb_config = os.path.join(APP_DIRECTORY, 'config.json')
        if os.path.exists(usb_config):
            return usb_config
    
    # Use AppData on Windows, ~/.config on Linux/macOS
    if os.name == 'nt':
        app_data = os.getenv('APPDATA')
        config_dir = os.path.join(app_data, 'ThreatScanUsb')
    else:
        config_dir = os.path.expanduser('~/.config/threatscantusb')
    
    # Ensure directory exists
    os.makedirs(config_dir, exist_ok=True)
    
    return os.path.join(config_dir, 'config.json')

def get_app_data_dir():
    """
    Get the application data directory.
    
    If running from a USB drive, use a subdirectory in the app directory.
    Otherwise, use the system's app data location.
    """
    global APP_DIRECTORY
    
    if APP_DIRECTORY:
        # Check if we can write to the app directory (e.g. on a USB drive)
        app_data_dir = os.path.join(APP_DIRECTORY, 'data')
        try:
            os.makedirs(app_data_dir, exist_ok=True)
            test_file = os.path.join(app_data_dir, '.write_test')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            # If we can write, use the USB location
            return app_data_dir
        except (IOError, PermissionError):
            # If we can't write, fall back to system location
            pass
    
    # Use system app data location
    if os.name == 'nt':
        app_data = os.getenv('APPDATA')
        data_dir = os.path.join(app_data, 'ThreatScanUsb')
    else:
        data_dir = os.path.expanduser('~/.local/share/threatscantusb')
    
    # Ensure directory exists
    os.makedirs(data_dir, exist_ok=True)
    
    return data_dir

def get_resource_path(resource_type, filename=None):
    """
    Get the path to a resource file.
    
    Args:
        resource_type: The type of resource (e.g., 'yara_rules', 'icons')
        filename: Optional filename to append
        
    Returns:
        The path to the resource
    """
    global APP_DIRECTORY
    
    if APP_DIRECTORY:
        # First check if the resource exists in the app directory
        if filename:
            resource_path = os.path.join(APP_DIRECTORY, 'resources', resource_type, filename)
        else:
            resource_path = os.path.join(APP_DIRECTORY, 'resources', resource_type)
            
        if os.path.exists(resource_path):
            return resource_path
    
    # Fall back to system location
    app_data_dir = get_app_data_dir()
    
    if filename:
        return os.path.join(app_data_dir, 'resources', resource_type, filename)
    else:
        resource_dir = os.path.join(app_data_dir, 'resources', resource_type)
        os.makedirs(resource_dir, exist_ok=True)
        return resource_dir

def load_configuration():
    """
    Load configuration from file, falling back to defaults if needed.
    
    Returns:
        dict: The application configuration
    """
    config_path = get_config_path()
    config = DEFAULT_CONFIG.copy()
    
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                
            # Update default config with user settings
            config.update(user_config)
            logger.info(f"Loaded configuration from {config_path}")
        else:
            logger.info(f"No configuration file found at {config_path}, using defaults")
            
            # Update resource paths to use the application directory
            if APP_DIRECTORY:
                config['yara_rules_path'] = get_resource_path('yara_rules')
                
            # Create default config file
            save_configuration(config)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}", exc_info=True)
        logger.info("Using default configuration")
    
    return config

def save_configuration(config):
    """
    Save configuration to file.
    
    Args:
        config (dict): The configuration to save
    
    Returns:
        bool: True if successful, False otherwise
    """
    config_path = get_config_path()
    
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        logger.info(f"Saved configuration to {config_path}")
        return True
    except Exception as e:
        logger.error(f"Error saving configuration: {e}", exc_info=True)
        return False

def update_configuration(updates):
    """
    Update specific configuration settings.
    
    Args:
        updates (dict): Configuration keys and values to update
    
    Returns:
        dict: The updated configuration
    """
    config = load_configuration()
    config.update(updates)
    save_configuration(config)
    return config 