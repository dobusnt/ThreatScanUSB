#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ThreatScanUsb - Main Entry Point

This is the main entry point for the application.
It can run from any location, including a USB drive.
"""

import sys
import os
import logging
from pathlib import Path

# Determine application directory - where the script is located
# This allows running from any location, including a USB drive
app_dir = os.path.dirname(os.path.abspath(__file__))

# Add the src directory to the path
src_path = os.path.join(app_dir, 'src')
sys.path.insert(0, src_path)

# Set up logging - save log in the same directory as the application
log_file = os.path.join(app_dir, 'threatscanner.log')
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(
    level=logging.INFO,
    format=log_format,
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(log_file)
    ]
)

logger = logging.getLogger('ThreatScanUsb')

def main():
    """
    Main application entry point.
    
    This loads the required modules and starts the application.
    """
    logger.info("Starting ThreatScanUsb application")
    logger.info(f"Application directory: {app_dir}")
    
    try:
        # Import modules
        from src.config import load_configuration, set_app_directory
        from src.scanner import ScanEngine
        from src.usb_monitor import USBMonitor
        from src.gui import ApplicationGUI
        
        # Set global application directory
        set_app_directory(app_dir)
        
        # Load configuration
        config = load_configuration()
        
        # Initialize scan engine
        scan_engine = ScanEngine(config)
        
        # Initialize USB monitor
        usb_monitor = USBMonitor(scan_engine)
        
        # Start GUI
        app_gui = ApplicationGUI(usb_monitor, scan_engine)
        
        # Run the application
        return app_gui.run()
        
    except ImportError as e:
        logger.critical(f"Failed to import required module: {e}")
        print(f"ERROR: Could not load required module: {e}")
        print("Please make sure you have installed all dependencies with 'pip install -r requirements.txt'")
        return 1
    
    except Exception as e:
        logger.critical(f"Failed to start application: {e}", exc_info=True)
        print(f"ERROR: Could not start application: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 