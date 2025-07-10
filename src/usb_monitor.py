#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
USB Monitor Module

This module handles the detection of USB devices and triggers the scanning process
when a new USB device is connected to the system.
"""

import logging
import threading
import time
import os
import string
from pathlib import Path
import win32api
import win32con
import win32file

logger = logging.getLogger('ThreatScanUsb.USBMonitor')

class USBMonitor:
    """Monitor for USB device connections."""
    
    def __init__(self, scan_engine):
        """
        Initialize the USB monitor.
        
        Args:
            scan_engine: The scan engine to use when a USB device is connected.
        """
        self.scan_engine = scan_engine
        self.monitor_thread = None
        self.stop_event = threading.Event()
        self.connected_drives = set()
        self.check_interval = 1.0  # Check for new devices every 1 second
        
        # Initially detect all currently connected drives
        self._update_connected_drives()
        
    def _update_connected_drives(self):
        """Get a set of all currently connected drive letters."""
        drives = []
        bitmask = win32api.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drives.append(f"{letter}:")
            bitmask >>= 1
        
        return set(drives)
    
    def _is_removable_drive(self, drive):
        """Check if a drive is removable."""
        try:
            return win32file.GetDriveType(f"{drive}\\") == win32con.DRIVE_REMOVABLE
        except Exception as e:
            logger.error(f"Error checking if drive {drive} is removable: {e}")
            return False
    
    def _monitoring_loop(self):
        """Main monitoring loop for USB devices."""
        logger.info("USB monitoring loop started")
        
        while not self.stop_event.is_set():
            try:
                # Get current drives
                current_drives = self._update_connected_drives()
                
                # Check for new drives
                new_drives = current_drives - self.connected_drives
                for drive in new_drives:
                    if self._is_removable_drive(drive):
                        logger.info(f"New USB drive detected: {drive}")
                        self._handle_new_usb_drive(drive)
                
                # Update our record of connected drives
                self.connected_drives = current_drives
                
                # Sleep before next check
                self.stop_event.wait(self.check_interval)
                
            except Exception as e:
                logger.error(f"Error in USB monitoring loop: {e}", exc_info=True)
                # Sleep a bit longer if we hit an error
                self.stop_event.wait(5)
    
    def _handle_new_usb_drive(self, drive):
        """Handle a newly connected USB drive."""
        try:
            # Get drive info
            volume_info = win32api.GetVolumeInformation(f"{drive}\\")
            volume_name = volume_info[0]
            logger.info(f"New USB drive: {drive} - {volume_name if volume_name else 'No Label'}")
            
            # Trigger scan
            self.scan_engine.scan_device(drive)
            
        except Exception as e:
            logger.error(f"Error handling new USB drive {drive}: {e}")
    
    def start_monitoring(self):
        """Start monitoring for USB connections."""
        if self.monitor_thread is None or not self.monitor_thread.is_alive():
            self.stop_event.clear()
            self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitor_thread.start()
            logger.info("USB monitoring started")
        else:
            logger.warning("USB monitoring already running")
    
    def stop_monitoring(self):
        """Stop monitoring for USB connections."""
        if self.monitor_thread and self.monitor_thread.is_alive():
            logger.info("Stopping USB monitoring...")
            self.stop_event.set()
            self.monitor_thread.join(timeout=3.0)
            logger.info("USB monitoring stopped")
        else:
            logger.warning("USB monitoring not running")
    
    def is_monitoring(self):
        """Check if monitoring is currently active."""
        return self.monitor_thread is not None and self.monitor_thread.is_alive() 