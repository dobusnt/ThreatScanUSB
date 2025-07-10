#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ThreatScanUsb - Main Application

This is the main entry point for the USB Security Scanner application.
It initializes components and starts the monitoring process.
"""

import sys
import os
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('threatscanner.log')
    ]
)
logger = logging.getLogger('ThreatScanUsb')

# Import application modules
try:
    from usb_monitor import USBMonitor
    from scanner import ScanEngine
    from gui import ApplicationGUI
    from config import load_configuration
except ImportError as e:
    logger.critical(f"Failed to import required module: {e}")
    sys.exit(1)

def main():
    """Main application entry point."""
    logger.info("Starting ThreatScanUsb")
    
    # Load configuration
    config = load_configuration()
    
    # Initialize scan engine
    scan_engine = ScanEngine(config)
    
    # Initialize USB monitor
    usb_monitor = USBMonitor(scan_engine)
    
    # Start GUI (which will start the USB monitor)
    app = ApplicationGUI(usb_monitor, scan_engine)
    
    # Start everything
    try:
        logger.info("Starting USB monitoring")
        usb_monitor.start_monitoring()
        logger.info("Starting GUI")
        app.run()
    except KeyboardInterrupt:
        logger.info("Application terminated by user")
    except Exception as e:
        logger.error(f"Error in main application: {e}", exc_info=True)
    finally:
        # Clean shutdown
        logger.info("Shutting down application...")
        usb_monitor.stop_monitoring()
        logger.info("Application shutdown complete")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 