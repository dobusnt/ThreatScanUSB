#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
GUI Module

This module provides the user interface for the USB Security Scanner application.
"""

import sys
import os
import logging
import time
import webbrowser
from datetime import datetime
from pathlib import Path
import win32api
import win32file
import win32con
import string

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QTabWidget, QPushButton, QLabel, QTableWidget, QTableWidgetItem,
    QMessageBox, QFileDialog, QDialog, QLineEdit, QComboBox, QCheckBox,
    QGroupBox, QFormLayout, QSystemTrayIcon, QMenu, QHeaderView, QFrame,
    QSplitter, QProgressBar, QTextEdit, QSpacerItem, QSizePolicy, QInputDialog
)
from PyQt6.QtCore import Qt, QTimer, QSize, pyqtSignal, QThread
from PyQt6.QtGui import QIcon, QAction, QFont, QColor, QPalette, QPixmap

from config import load_configuration, save_configuration, update_configuration, get_app_data_dir, get_resource_path

logger = logging.getLogger('ThreatScanUsb.GUI')

class ApplicationGUI:
    """Main application GUI class."""
    
    def __init__(self, usb_monitor, scan_engine):
        """
        Initialize the GUI.
        
        Args:
            usb_monitor: The USB monitor instance
            scan_engine: The scan engine instance
        """
        self.usb_monitor = usb_monitor
        self.scan_engine = scan_engine
        self.config = load_configuration()
        self.app = QApplication(sys.argv)
        self.window = MainWindow(self, usb_monitor, scan_engine)
        
        # Set application icon
        try:
            icon_path = get_resource_path('icons', 'app_icon.png')
            if os.path.exists(icon_path):
                self.app.setWindowIcon(QIcon(icon_path))
        except Exception as e:
            logger.error(f"Failed to load application icon: {e}")
        
        # Set up system tray if supported
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.setup_system_tray()
        
        # Set window theme
        self.apply_theme()
    
    def setup_system_tray(self):
        """Set up system tray icon and menu."""
        try:
            icon_path = get_resource_path('icons', 'app_icon.png')
            if os.path.exists(icon_path):
                icon = QIcon(icon_path)
            else:
                # Fallback to a blank icon if we can't find the application icon
                icon = QIcon()
                
            self.tray_icon = QSystemTrayIcon(icon, self.app)
            tray_menu = QMenu()
            
            # Add menu actions
            show_action = QAction("Show Window", self.app)
            show_action.triggered.connect(self.window.show)
            tray_menu.addAction(show_action)
            
            scan_action = QAction("Scan USB Drives", self.app)
            scan_action.triggered.connect(self.window.scan_connected_usb)
            tray_menu.addAction(scan_action)
            
            tray_menu.addSeparator()
            
            exit_action = QAction("Exit", self.app)
            exit_action.triggered.connect(self.app.quit)
            tray_menu.addAction(exit_action)
            
            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.show()
            
            # Set up signal for clicking tray icon
            self.tray_icon.activated.connect(self.tray_icon_activated)
        except Exception as e:
            logger.error(f"Failed to setup system tray: {e}")
    
    def tray_icon_activated(self, reason):
        """Handle tray icon activation."""
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self.window.isVisible():
                self.window.hide()
            else:
                self.window.show()
    
    def show_notification(self, title, message):
        """Show a system tray notification."""
        if hasattr(self, 'tray_icon'):
            self.tray_icon.showMessage(title, message, QSystemTrayIcon.MessageIcon.Information, 5000)
    
    def apply_theme(self):
        """Apply the selected theme."""
        theme = self.config.get('theme', 'system')
        
        if theme == 'dark':
            self.set_dark_theme()
        elif theme == 'light':
            self.set_light_theme()
        # System theme is handled by default
    
    def set_dark_theme(self):
        """Apply dark theme."""
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(25, 25, 25))
        palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
        
        self.app.setPalette(palette)
    
    def set_light_theme(self):
        """Apply light theme."""
        self.app.setPalette(self.app.style().standardPalette())
    
    def run(self):
        """Run the application."""
        self.window.show()
        
        # Start USB monitoring if auto-scan is enabled
        if self.config.get('auto_scan_usb', True):
            self.usb_monitor.start_monitoring()
        
        # Start the application event loop
        return self.app.exec()


class MainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self, app_gui, usb_monitor, scan_engine):
        """Initialize the main window."""
        super().__init__()
        
        self.app_gui = app_gui
        self.usb_monitor = usb_monitor
        self.scan_engine = scan_engine
        self.config = load_configuration()
        
        # Window setup
        self.setWindowTitle("USB Security Scanner")
        self.setMinimumSize(800, 600)
        
        # Create central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Main layout
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Create tabs
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # Create each tab
        self.create_dashboard_tab()
        self.create_scan_results_tab()
        self.create_quarantine_tab()
        self.create_settings_tab()
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label, 1)
        
        # Set up timer for updating status
        self.status_timer = QTimer(self)
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(1000)  # Update every second
    
    def create_dashboard_tab(self):
        """Create the dashboard tab."""
        dashboard = QWidget()
        layout = QVBoxLayout(dashboard)
        
        # Header
        header_layout = QHBoxLayout()
        logo_label = QLabel("USB Security Scanner")
        logo_label.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        header_layout.addWidget(logo_label)
        header_layout.addStretch(1)
        layout.addLayout(header_layout)
        
        # Status section
        status_group = QGroupBox("System Status")
        status_layout = QVBoxLayout(status_group)
        
        # USB Monitoring status
        self.monitor_status_layout = QHBoxLayout()
        self.monitor_status_label = QLabel("USB Monitoring: ")
        self.monitor_status_value = QLabel("Inactive")
        self.monitor_status_layout.addWidget(self.monitor_status_label)
        self.monitor_status_layout.addWidget(self.monitor_status_value)
        self.monitor_status_layout.addStretch(1)
        
        # Toggle button
        self.toggle_monitoring_btn = QPushButton("Start Monitoring")
        self.toggle_monitoring_btn.clicked.connect(self.toggle_usb_monitoring)
        self.monitor_status_layout.addWidget(self.toggle_monitoring_btn)
        
        status_layout.addLayout(self.monitor_status_layout)
        
        # Scan progress
        scan_progress_layout = QHBoxLayout()
        scan_progress_label = QLabel("Scan Progress:")
        scan_progress_layout.addWidget(scan_progress_label)
        
        self.scan_progress_bar = QProgressBar()
        self.scan_progress_bar.setRange(0, 100)
        self.scan_progress_bar.setValue(0)
        scan_progress_layout.addWidget(self.scan_progress_bar, 1)
        
        self.scan_status_label = QLabel("No scan in progress")
        scan_progress_layout.addWidget(self.scan_status_label)
        
        status_layout.addLayout(scan_progress_layout)
        
        layout.addWidget(status_group)
        
        # Action buttons
        action_layout = QHBoxLayout()
        
        # Scan USB button
        scan_usb_btn = QPushButton("Scan Connected USB Devices")
        scan_usb_btn.setMinimumHeight(50)
        scan_usb_btn.clicked.connect(self.scan_connected_usb)
        action_layout.addWidget(scan_usb_btn)
        
        # Scan folder button
        scan_folder_btn = QPushButton("Scan Folder")
        scan_folder_btn.setMinimumHeight(50)
        scan_folder_btn.clicked.connect(self.scan_folder)
        action_layout.addWidget(scan_folder_btn)
        
        # Stop scan button
        self.stop_scan_btn = QPushButton("Stop Scan")
        self.stop_scan_btn.setMinimumHeight(50)
        self.stop_scan_btn.setEnabled(False)
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        action_layout.addWidget(self.stop_scan_btn)
        
        layout.addLayout(action_layout)
        
        # Recent activity
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout(activity_group)
        
        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        activity_layout.addWidget(self.activity_log)
        
        layout.addWidget(activity_group)
        
        # Add tab
        self.tabs.addTab(dashboard, "Dashboard")
    
    def create_scan_results_tab(self):
        """Create the scan results tab."""
        results_tab = QWidget()
        layout = QVBoxLayout(results_tab)
        
        # Create table for results
        self.results_table = QTableWidget(0, 5)
        self.results_table.setHorizontalHeaderLabels(["Threat Type", "File Path", "Confidence", "Date/Time", "Actions"])
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        
        # Enable row selection and double-click to view details
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.results_table.doubleClicked.connect(self._show_threat_details)
        
        layout.addWidget(self.results_table)
        
        # Buttons for actions
        button_layout = QHBoxLayout()
        
        quarantine_all_btn = QPushButton("Quarantine All")
        quarantine_all_btn.clicked.connect(self.quarantine_all_threats)
        button_layout.addWidget(quarantine_all_btn)
        
        delete_all_btn = QPushButton("Delete All")
        delete_all_btn.clicked.connect(self.delete_all_threats)
        button_layout.addWidget(delete_all_btn)
        
        export_btn = QPushButton("Export Results")
        export_btn.clicked.connect(self.export_results)
        button_layout.addWidget(export_btn)
        
        clear_btn = QPushButton("Clear Results")
        clear_btn.clicked.connect(self.clear_results)
        button_layout.addWidget(clear_btn)
        
        layout.addLayout(button_layout)
        
        # Add tab
        self.tabs.addTab(results_tab, "Scan Results")
    
    def create_quarantine_tab(self):
        """Create the quarantine tab."""
        quarantine_tab = QWidget()
        layout = QVBoxLayout(quarantine_tab)
        
        # Create table for quarantined files
        self.quarantine_table = QTableWidget(0, 4)
        self.quarantine_table.setHorizontalHeaderLabels(["Original Path", "Threat Type", "Quarantine Date", "Actions"])
        self.quarantine_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.quarantine_table)
        
        # Buttons for actions
        button_layout = QHBoxLayout()
        
        restore_btn = QPushButton("Restore Selected")
        restore_btn.clicked.connect(self.restore_selected)
        button_layout.addWidget(restore_btn)
        
        delete_btn = QPushButton("Delete Selected")
        delete_btn.clicked.connect(self.delete_selected)
        button_layout.addWidget(delete_btn)
        
        delete_all_btn = QPushButton("Delete All Quarantined")
        delete_all_btn.clicked.connect(self.delete_all_quarantined)
        button_layout.addWidget(delete_all_btn)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_quarantine)
        button_layout.addWidget(refresh_btn)
        
        layout.addLayout(button_layout)
        
        # Add tab
        self.tabs.addTab(quarantine_tab, "Quarantine")
        
        # Load quarantined files
        self.refresh_quarantine()
    
    def create_settings_tab(self):
        """Create the settings tab."""
        settings_tab = QWidget()
        layout = QVBoxLayout(settings_tab)
        
        # Scanning settings
        scan_group = QGroupBox("Scanning Settings")
        scan_layout = QFormLayout(scan_group)
        
        # Auto scan USB
        self.auto_scan_check = QCheckBox()
        self.auto_scan_check.setChecked(self.config.get('auto_scan_usb', True))
        scan_layout.addRow("Auto-scan USB devices:", self.auto_scan_check)
        
        # Skip hidden directories
        self.skip_hidden_check = QCheckBox()
        self.skip_hidden_check.setChecked(self.config.get('skip_hidden_dirs', True))
        scan_layout.addRow("Skip hidden directories:", self.skip_hidden_check)
        
        # Max file size
        self.max_file_size = QComboBox()
        for size in [10, 50, 100, 250, 500, 1000]:
            self.max_file_size.addItem(f"{size} MB", size)
        current_size = self.config.get('max_file_size_mb', 100)
        index = self.max_file_size.findData(current_size)
        if index >= 0:
            self.max_file_size.setCurrentIndex(index)
        scan_layout.addRow("Maximum file size to scan:", self.max_file_size)
        
        layout.addWidget(scan_group)
        
        # Detection settings
        detect_group = QGroupBox("Detection Settings")
        detect_layout = QFormLayout(detect_group)
        
        # Use YARA
        self.use_yara_check = QCheckBox()
        self.use_yara_check.setChecked(self.config.get('use_yara', True))
        detect_layout.addRow("Use YARA rules:", self.use_yara_check)
        
        # Use ClamAV
        self.use_clamav_check = QCheckBox()
        self.use_clamav_check.setChecked(self.config.get('use_clamav', False))
        detect_layout.addRow("Use ClamAV:", self.use_clamav_check)
        
        # Use VirusTotal
        self.use_vt_check = QCheckBox()
        self.use_vt_check.setChecked(self.config.get('use_virustotal', False))
        detect_layout.addRow("Use VirusTotal API:", self.use_vt_check)
        
        # VirusTotal API Key
        self.vt_api_key = QLineEdit()
        self.vt_api_key.setText(self.config.get('virustotal_api_key', ''))
        self.vt_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        detect_layout.addRow("VirusTotal API Key:", self.vt_api_key)
        
        layout.addWidget(detect_group)
        
        # UI settings
        ui_group = QGroupBox("User Interface Settings")
        ui_layout = QFormLayout(ui_group)
        
        # Theme
        self.theme_combo = QComboBox()
        self.theme_combo.addItem("System", "system")
        self.theme_combo.addItem("Light", "light")
        self.theme_combo.addItem("Dark", "dark")
        current_theme = self.config.get('theme', 'system')
        index = self.theme_combo.findData(current_theme)
        if index >= 0:
            self.theme_combo.setCurrentIndex(index)
        ui_layout.addRow("Theme:", self.theme_combo)
        
        # Notifications
        self.notify_check = QCheckBox()
        self.notify_check.setChecked(self.config.get('notify_threats', True))
        ui_layout.addRow("Show threat notifications:", self.notify_check)
        
        layout.addWidget(ui_group)
        
        # Save button
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
        # Add stretch
        layout.addStretch(1)
        
        # Add tab
        self.tabs.addTab(settings_tab, "Settings")
    
    def toggle_usb_monitoring(self):
        """Toggle USB monitoring on/off."""
        if self.usb_monitor.is_monitoring():
            self.usb_monitor.stop_monitoring()
            self.toggle_monitoring_btn.setText("Start Monitoring")
            self.monitor_status_value.setText("Inactive")
            self.log_activity("USB monitoring stopped")
        else:
            self.usb_monitor.start_monitoring()
            self.toggle_monitoring_btn.setText("Stop Monitoring")
            self.monitor_status_value.setText("Active")
            self.log_activity("USB monitoring started")
    
    def scan_connected_usb(self):
        """Scan all connected USB devices."""
        # Find all connected USB drives
        try:
            usb_drives = []
            bitmask = win32api.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    drive = f"{letter}:"
                    if win32file.GetDriveType(f"{drive}\\") == win32con.DRIVE_REMOVABLE:
                        usb_drives.append(drive)
                bitmask >>= 1
            
            if not usb_drives:
                QMessageBox.information(self, "No USB Drives", "No USB drives were detected.")
                self.log_activity("No USB drives detected for scanning")
                return
            
            # If there are multiple drives, ask the user which one to scan
            drive_to_scan = None
            if len(usb_drives) == 1:
                drive_to_scan = usb_drives[0]
            else:
                drive, ok = QInputDialog.getItem(
                    self, "Select USB Drive", 
                    "Multiple USB drives detected. Select one to scan:", 
                    usb_drives, 0, False
                )
                if ok and drive:
                    drive_to_scan = drive
            
            if drive_to_scan:
                # Start scanning the selected drive
                self.log_activity(f"Scanning USB drive: {drive_to_scan}")
                success = self.scan_engine.scan_device(drive_to_scan)
                if success:
                    self.stop_scan_btn.setEnabled(True)
                    QMessageBox.information(
                        self, "Scan Started", 
                        f"Scanning of {drive_to_scan} has started. See the status in the dashboard."
                    )
                else:
                    QMessageBox.warning(
                        self, "Scan Failed", 
                        "Failed to start scan. Another scan may be in progress."
                    )
        except Exception as e:
            logger.error(f"Error detecting USB drives: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Error detecting USB drives: {str(e)}")
            self.log_activity(f"Error detecting USB drives: {str(e)}")
    
    def scan_folder(self):
        """Open a folder browser and scan the selected folder."""
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder:
            self.log_activity(f"Scanning folder: {folder}")
            
            # Start scanning the selected folder
            success = self.scan_engine.scan_directory(folder)
            if success:
                self.stop_scan_btn.setEnabled(True)
                QMessageBox.information(
                    self, "Scan Started", 
                    f"Scanning of {folder} has started. See the status in the dashboard."
                )
            else:
                QMessageBox.warning(
                    self, "Scan Failed", 
                    "Failed to start scan. Another scan may be in progress."
                )
    
    def stop_scan(self):
        """Stop the current scan."""
        if self.scan_engine.stop_scan():
            self.log_activity("Scan stopped by user")
            self.stop_scan_btn.setEnabled(False)
    
    def quarantine_all_threats(self):
        """Quarantine all threats in the results table."""
        # Get all paths from the results table
        threat_paths = []
        for row in range(self.results_table.rowCount()):
            # Skip already quarantined or deleted items
            action_cell = self.results_table.item(row, 4)
            if action_cell and action_cell.text() in ["Quarantined", "Deleted"]:
                continue
                
            path = self.results_table.item(row, 1).text()
            threat_paths.append((row, path))
        
        if not threat_paths:
            QMessageBox.information(
                self, "No Action Needed", 
                "No threats to quarantine or all threats have already been processed."
            )
            return
        
        # Ask for confirmation
        reply = QMessageBox.question(
            self, "Confirm Quarantine", 
            f"Are you sure you want to quarantine {len(threat_paths)} files?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # Process each threat
            success_count = 0
            fail_count = 0
            
            for row, path in threat_paths:
                success = self.scan_engine.quarantine_file(path)
                if success:
                    # Update the action cell
                    self.results_table.removeCellWidget(row, 4)
                    self.results_table.setItem(row, 4, QTableWidgetItem("Quarantined"))
                    success_count += 1
                else:
                    fail_count += 1
            
            self.log_activity(f"Quarantined {success_count} threats, {fail_count} failed")
            QMessageBox.information(
                self, "Quarantine Complete", 
                f"Quarantined {success_count} files. {fail_count} files failed."
            )
            
            # Refresh quarantine tab
            self.refresh_quarantine()
    
    def delete_all_threats(self):
        """Delete all threats in the results table."""
        # Get all paths from the results table
        threat_paths = []
        for row in range(self.results_table.rowCount()):
            # Skip already quarantined or deleted items
            action_cell = self.results_table.item(row, 4)
            if action_cell and action_cell.text() in ["Quarantined", "Deleted"]:
                continue
                
            path = self.results_table.item(row, 1).text()
            threat_paths.append((row, path))
        
        if not threat_paths:
            QMessageBox.information(
                self, "No Action Needed", 
                "No threats to delete or all threats have already been processed."
            )
            return
        
        # Ask for confirmation
        reply = QMessageBox.question(
            self, "Confirm Deletion", 
            f"Are you sure you want to permanently delete {len(threat_paths)} files?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # Process each threat
            success_count = 0
            fail_count = 0
            
            for row, path in threat_paths:
                try:
                    os.remove(path)
                    # Update the action cell
                    self.results_table.removeCellWidget(row, 4)
                    self.results_table.setItem(row, 4, QTableWidgetItem("Deleted"))
                    success_count += 1
                except Exception as e:
                    logger.error(f"Error deleting file {path}: {e}")
                    fail_count += 1
            
            self.log_activity(f"Deleted {success_count} threats, {fail_count} failed")
            QMessageBox.information(
                self, "Deletion Complete", 
                f"Deleted {success_count} files. {fail_count} files failed."
            )
    
    def export_results(self):
        """Export scan results to a file."""
        # Get current results
        results = self.scan_engine.get_scan_results()
        threats = [r for r in results if r.is_threat]
        
        if not threats:
            QMessageBox.information(
                self, "No Results", 
                "No threats found to export."
            )
            return
        
        # Ask user for save location
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        default_filename = f"threatscanner_results_{timestamp}.csv"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Scan Results", 
            default_filename, 
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if not file_path:
            return  # User canceled
        
        try:
            with open(file_path, 'w', newline='') as f:
                import csv
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    "Threat Type", "File Path", "Threat Name", 
                    "Confidence", "Scan Time", "Details"
                ])
                
                # Write data
                for result in threats:
                    timestamp = datetime.fromtimestamp(result.scan_time).strftime("%Y-%m-%d %H:%M:%S")
                    writer.writerow([
                        result.threat_type,
                        result.path,
                        result.threat_name,
                        f"{result.confidence}%",
                        timestamp,
                        str(result.details)
                    ])
            
            self.log_activity(f"Exported scan results to {file_path}")
            QMessageBox.information(
                self, "Export Complete", 
                f"Results exported successfully to:\n{file_path}"
            )
            
        except Exception as e:
            logger.error(f"Error exporting results: {e}", exc_info=True)
            QMessageBox.critical(
                self, "Export Failed", 
                f"Failed to export results: {str(e)}"
            )
    
    def clear_results(self):
        """Clear the results table."""
        self.results_table.setRowCount(0)
        self.log_activity("Scan results cleared")
    
    def restore_selected(self):
        """Restore selected quarantined files."""
        # Get selected rows
        selected_rows = set()
        for item in self.quarantine_table.selectedItems():
            selected_rows.add(item.row())
        
        if not selected_rows:
            QMessageBox.information(
                self, "No Selection", 
                "No files selected to restore."
            )
            return
        
        # Ask user where to restore the files
        restore_dir = QFileDialog.getExistingDirectory(
            self, "Select Directory to Restore Files"
        )
        
        if not restore_dir:
            return  # User canceled
        
        # Process each selected row
        success_count = 0
        fail_count = 0
        
        for row in selected_rows:
            try:
                # Get the restore button to access properties
                action_cell = self.quarantine_table.cellWidget(row, 3)
                if not action_cell:
                    continue
                    
                restore_btn = action_cell.layout().itemAt(0).widget()
                file_path = restore_btn.property("file_path")
                original_name = restore_btn.property("original_name")
                
                restore_path = os.path.join(restore_dir, original_name)
                
                # Check if file exists
                if os.path.exists(restore_path):
                    # Generate unique name
                    base, ext = os.path.splitext(original_name)
                    i = 1
                    while os.path.exists(restore_path):
                        restore_path = os.path.join(restore_dir, f"{base}_{i}{ext}")
                        i += 1
                
                # Move file
                os.rename(file_path, restore_path)
                success_count += 1
                
            except Exception as e:
                logger.error(f"Error restoring file in row {row}: {e}", exc_info=True)
                fail_count += 1
        
        self.log_activity(f"Restored {success_count} files from quarantine, {fail_count} failed")
        QMessageBox.information(
            self, "Restore Complete", 
            f"Restored {success_count} files. {fail_count} files failed."
        )
        
        # Refresh quarantine list
        self.refresh_quarantine()
    
    def delete_selected(self):
        """Delete selected quarantined files."""
        # Get selected rows
        selected_rows = set()
        for item in self.quarantine_table.selectedItems():
            selected_rows.add(item.row())
        
        if not selected_rows:
            QMessageBox.information(
                self, "No Selection", 
                "No files selected to delete."
            )
            return
        
        # Ask for confirmation
        reply = QMessageBox.question(
            self, "Confirm Deletion", 
            f"Are you sure you want to permanently delete {len(selected_rows)} quarantined files?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # Process each selected row
        success_count = 0
        fail_count = 0
        
        for row in selected_rows:
            try:
                # Get the delete button to access properties
                action_cell = self.quarantine_table.cellWidget(row, 3)
                if not action_cell:
                    continue
                    
                delete_btn = action_cell.layout().itemAt(1).widget()
                file_path = delete_btn.property("file_path")
                
                # Delete file
                os.remove(file_path)
                success_count += 1
                
            except Exception as e:
                logger.error(f"Error deleting file in row {row}: {e}", exc_info=True)
                fail_count += 1
        
        self.log_activity(f"Deleted {success_count} files from quarantine, {fail_count} failed")
        QMessageBox.information(
            self, "Deletion Complete", 
            f"Deleted {success_count} files. {fail_count} files failed."
        )
        
        # Refresh quarantine list
        self.refresh_quarantine()
    
    def delete_all_quarantined(self):
        """Delete all quarantined files."""
        try:
            # Find quarantine directory
            app_data = os.getenv('APPDATA') or os.path.expanduser('~')
            quarantine_dir = self.config.get('quarantine_dir')
            if not quarantine_dir:
                quarantine_dir = os.path.join(app_data, 'ThreatScanUsb', 'quarantine')
            
            if not os.path.exists(quarantine_dir):
                QMessageBox.information(
                    self, "No Files", 
                    "No quarantined files to delete."
                )
                return
            
            # Count files
            quarantined_files = os.listdir(quarantine_dir)
            if not quarantined_files:
                QMessageBox.information(
                    self, "No Files", 
                    "No quarantined files to delete."
                )
                return
            
            # Ask for confirmation
            reply = QMessageBox.question(
                self, "Confirm Deletion", 
                f"Are you sure you want to permanently delete all {len(quarantined_files)} quarantined files?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply != QMessageBox.StandardButton.Yes:
                return
            
            # Delete all files
            success_count = 0
            fail_count = 0
            
            for file_name in quarantined_files:
                try:
                    file_path = os.path.join(quarantine_dir, file_name)
                    os.remove(file_path)
                    success_count += 1
                except Exception as e:
                    logger.error(f"Error deleting file {file_name}: {e}", exc_info=True)
                    fail_count += 1
            
            self.log_activity(f"Deleted all {success_count} files from quarantine, {fail_count} failed")
            QMessageBox.information(
                self, "Deletion Complete", 
                f"Deleted {success_count} files. {fail_count} files failed."
            )
            
            # Refresh quarantine list
            self.refresh_quarantine()
            
        except Exception as e:
            logger.error(f"Error deleting all quarantined files: {e}", exc_info=True)
            QMessageBox.critical(
                self, "Error", 
                f"Failed to delete quarantined files: {str(e)}"
            )
    
    def refresh_quarantine(self):
        """Refresh the quarantine list."""
        # Clear current table
        self.quarantine_table.setRowCount(0)
        
        try:
            # Find quarantine directory
            quarantine_dir = self.config.get('quarantine_dir')
            if not quarantine_dir:
                app_data_dir = get_app_data_dir()
                quarantine_dir = os.path.join(app_data_dir, 'quarantine')
            
            if not os.path.exists(quarantine_dir):
                # No quarantine directory yet
                return
            
            # List all files in quarantine
            quarantined_files = os.listdir(quarantine_dir)
            
            for file_name in quarantined_files:
                # Parse the timestamp and original filename from quarantine filename
                parts = file_name.split('_', 1)
                if len(parts) != 2:
                    continue
                    
                timestamp_str, original_name = parts
                
                # Try to parse timestamp
                try:
                    timestamp = datetime.strptime(timestamp_str, "%Y%m%d-%H%M%S")
                    formatted_date = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    formatted_date = "Unknown"
                
                # Get file path
                file_path = os.path.join(quarantine_dir, file_name)
                
                # Insert into table
                row_position = self.quarantine_table.rowCount()
                self.quarantine_table.insertRow(row_position)
                
                # Add data to the row
                self.quarantine_table.setItem(row_position, 0, QTableWidgetItem(original_name))
                
                # Try to determine threat type from file extension
                ext = os.path.splitext(original_name)[1].lower()
                threat_type = "Unknown"
                if ext in self.scan_engine.SUSPICIOUS_EXTENSIONS:
                    threat_type = "Suspicious Executable"
                elif original_name.lower() in self.scan_engine.AUTORUN_FILES:
                    threat_type = "Autorun File"
                
                self.quarantine_table.setItem(row_position, 1, QTableWidgetItem(threat_type))
                self.quarantine_table.setItem(row_position, 2, QTableWidgetItem(formatted_date))
                
                # Add action buttons
                action_widget = QWidget()
                action_layout = QHBoxLayout(action_widget)
                action_layout.setContentsMargins(0, 0, 0, 0)
                
                restore_btn = QPushButton("Restore")
                restore_btn.setProperty("file_path", file_path)
                restore_btn.setProperty("original_name", original_name)
                restore_btn.clicked.connect(self._restore_quarantined_file)
                
                delete_btn = QPushButton("Delete")
                delete_btn.setProperty("file_path", file_path)
                delete_btn.clicked.connect(self._delete_quarantined_file)
                
                action_layout.addWidget(restore_btn)
                action_layout.addWidget(delete_btn)
                
                self.quarantine_table.setCellWidget(row_position, 3, action_widget)
            
        except Exception as e:
            logger.error(f"Error refreshing quarantine: {e}", exc_info=True)
            QMessageBox.critical(
                self, "Error", 
                f"Failed to refresh quarantine: {str(e)}"
            )
    
    def _restore_quarantined_file(self):
        """Restore a quarantined file."""
        button = self.sender()
        if button:
            file_path = button.property("file_path")
            original_name = button.property("original_name")
            
            # Ask user where to restore the file
            restore_dir = QFileDialog.getExistingDirectory(
                self, "Select Directory to Restore File"
            )
            
            if not restore_dir:
                return  # User canceled
            
            restore_path = os.path.join(restore_dir, original_name)
            
            # Check if file already exists at destination
            if os.path.exists(restore_path):
                reply = QMessageBox.question(
                    self, "File Exists", 
                    f"A file with the same name already exists. Overwrite?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                
                if reply != QMessageBox.StandardButton.Yes:
                    return
            
            try:
                # Move file from quarantine to restore location
                os.rename(file_path, restore_path)
                self.log_activity(f"Restored file from quarantine: {restore_path}")
                QMessageBox.information(
                    self, "File Restored", 
                    f"File restored to:\n{restore_path}"
                )
                # Refresh quarantine list
                self.refresh_quarantine()
            except Exception as e:
                logger.error(f"Error restoring file {file_path}: {e}", exc_info=True)
                QMessageBox.critical(
                    self, "Restore Failed", 
                    f"Failed to restore file: {str(e)}"
                )
    
    def _delete_quarantined_file(self):
        """Delete a quarantined file."""
        button = self.sender()
        if button:
            file_path = button.property("file_path")
            
            # Ask for confirmation
            reply = QMessageBox.question(
                self, "Confirm Deletion", 
                "Are you sure you want to permanently delete this quarantined file?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    os.remove(file_path)
                    self.log_activity(f"Deleted file from quarantine: {file_path}")
                    QMessageBox.information(
                        self, "File Deleted", 
                        "Quarantined file deleted successfully."
                    )
                    # Refresh quarantine list
                    self.refresh_quarantine()
                except Exception as e:
                    logger.error(f"Error deleting file {file_path}: {e}", exc_info=True)
                    QMessageBox.critical(
                        self, "Deletion Failed", 
                        f"Failed to delete file: {str(e)}"
                    )
    
    def save_settings(self):
        """Save current settings to configuration."""
        # Collect settings from UI
        updates = {
            'auto_scan_usb': self.auto_scan_check.isChecked(),
            'skip_hidden_dirs': self.skip_hidden_check.isChecked(),
            'max_file_size_mb': self.max_file_size.currentData(),
            'use_yara': self.use_yara_check.isChecked(),
            'use_clamav': self.use_clamav_check.isChecked(),
            'use_virustotal': self.use_vt_check.isChecked(),
            'virustotal_api_key': self.vt_api_key.text(),
            'theme': self.theme_combo.currentData(),
            'notify_threats': self.notify_check.isChecked(),
        }
        
        # Update configuration
        self.config = update_configuration(updates)
        
        # Apply theme if changed
        current_theme = self.app_gui.config.get('theme')
        if current_theme != updates['theme']:
            self.app_gui.config['theme'] = updates['theme']
            self.app_gui.apply_theme()
        
        self.log_activity("Settings saved")
        QMessageBox.information(self, "Settings Saved", "Your settings have been saved successfully.")
    
    def update_status(self):
        """Update status information in the UI."""
        # Update USB monitoring status
        if self.usb_monitor.is_monitoring():
            self.monitor_status_value.setText("Active")
            self.toggle_monitoring_btn.setText("Stop Monitoring")
        else:
            self.monitor_status_value.setText("Inactive")
            self.toggle_monitoring_btn.setText("Start Monitoring")
        
        # Update scan progress
        scan_info = self.scan_engine.get_scan_progress()
        
        if scan_info['status'] == 'scanning':
            self.scan_progress_bar.setValue(scan_info.get('progress', 0))
            files_scanned = scan_info.get('files_scanned', 0)
            total_files = scan_info.get('total_files', 0)
            
            if total_files > 0:
                status_text = f"Scanning {scan_info['drive']} - {files_scanned}/{total_files} files - {scan_info['threats_found']} threats"
            else:
                status_text = f"Scanning {scan_info['drive']} - {scan_info['threats_found']} threats found"
                
            self.scan_status_label.setText(status_text)
            self.stop_scan_btn.setEnabled(True)
            
            # Update results table if new threats were found
            self._update_results_table()
        else:
            # Scan completed or not running
            self.scan_progress_bar.setValue(100)
            self.scan_status_label.setText("No scan in progress")
            self.stop_scan_btn.setEnabled(False)
            
            # Final update of results table
            self._update_results_table()
        
        # Update status bar text
        if self.scan_engine.scan_in_progress:
            self.status_label.setText(f"Scanning in progress - {scan_info.get('threats_found', 0)} threats found")
        elif self.usb_monitor.is_monitoring():
            self.status_label.setText("Monitoring for USB devices")
        else:
            self.status_label.setText("Ready")
    
    def _update_results_table(self):
        """Update the results table with current scan results."""
        results = self.scan_engine.get_scan_results()
        threats = [r for r in results if r.is_threat]
        
        # Only add new threats to the table
        current_row_count = self.results_table.rowCount()
        for i in range(len(threats) - current_row_count):
            result = threats[current_row_count + i]
            row_position = self.results_table.rowCount()
            self.results_table.insertRow(row_position)
            
            # Store the scan result with the row for later reference
            self.results_table.setItem(row_position, 0, QTableWidgetItem(result.threat_type.capitalize()))
            self.results_table.item(row_position, 0).setData(Qt.ItemDataRole.UserRole, result)
            
            # Add data to the row
            self.results_table.setItem(row_position, 1, QTableWidgetItem(result.path))
            self.results_table.setItem(row_position, 2, QTableWidgetItem(f"{result.confidence}%"))
            
            # Format timestamp
            timestamp = datetime.fromtimestamp(result.scan_time).strftime("%Y-%m-%d %H:%M:%S")
            self.results_table.setItem(row_position, 3, QTableWidgetItem(timestamp))
            
            # Add action buttons
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(0, 0, 0, 0)
            
            quarantine_btn = QPushButton("Quarantine")
            quarantine_btn.setProperty("row", row_position)
            quarantine_btn.clicked.connect(self._quarantine_threat)
            
            delete_btn = QPushButton("Delete")
            delete_btn.setProperty("row", row_position)
            delete_btn.clicked.connect(self._delete_threat)
            
            action_layout.addWidget(quarantine_btn)
            action_layout.addWidget(delete_btn)
            
            self.results_table.setCellWidget(row_position, 4, action_widget)
            
            # Log the new threat
            if self.config.get('notify_threats', True):
                self.log_activity(f"Threat detected: {result.threat_name} in {result.path}")
                # Show notification if enabled
                self.app_gui.show_notification(
                    "Threat Detected", 
                    f"{result.threat_type.capitalize()}: {result.threat_name}"
                )
    
    def _quarantine_threat(self):
        """Quarantine the threat at the given row."""
        button = self.sender()
        if button:
            row = button.property("row")
            threat_path = self.results_table.item(row, 1).text()
            
            success = self.scan_engine.quarantine_file(threat_path)
            if success:
                self.log_activity(f"Quarantined threat: {threat_path}")
                QMessageBox.information(
                    self, "File Quarantined", 
                    "The file has been moved to quarantine."
                )
                # Update the action cell to show "Quarantined"
                self.results_table.removeCellWidget(row, 4)
                self.results_table.setItem(row, 4, QTableWidgetItem("Quarantined"))
                # Refresh quarantine tab
                self.refresh_quarantine()
            else:
                QMessageBox.warning(
                    self, "Quarantine Failed", 
                    f"Failed to quarantine file: {threat_path}"
                )
    
    def _delete_threat(self):
        """Delete the threat at the given row."""
        button = self.sender()
        if button:
            row = button.property("row")
            threat_path = self.results_table.item(row, 1).text()
            
            # Ask for confirmation
            reply = QMessageBox.question(
                self, "Confirm Deletion", 
                f"Are you sure you want to permanently delete this file?\n{threat_path}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    os.remove(threat_path)
                    self.log_activity(f"Deleted threat: {threat_path}")
                    # Update the action cell to show "Deleted"
                    self.results_table.removeCellWidget(row, 4)
                    self.results_table.setItem(row, 4, QTableWidgetItem("Deleted"))
                    QMessageBox.information(
                        self, "File Deleted", 
                        "The file has been deleted successfully."
                    )
                except Exception as e:
                    logger.error(f"Error deleting file {threat_path}: {e}", exc_info=True)
                    QMessageBox.critical(
                        self, "Deletion Failed", 
                        f"Failed to delete file: {str(e)}"
                    )
    
    def _show_threat_details(self, index):
        """Show detailed information about a threat when double-clicked."""
        row = index.row()
        if row >= 0:
            # Get the scan result object stored in the first column
            result_item = self.results_table.item(row, 0)
            if result_item:
                scan_result = result_item.data(Qt.ItemDataRole.UserRole)
                if scan_result:
                    # Create and show the threat details dialog
                    dialog = ThreatDetailsDialog(scan_result, self)
                    dialog.exec()
    
    def log_activity(self, message):
        """Add a message to the activity log."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.activity_log.append(f"[{timestamp}] {message}")
    
    def closeEvent(self, event):
        """Handle window close event."""
        if hasattr(self.app_gui, 'tray_icon') and self.config.get('minimize_to_tray', True):
            event.ignore()
            self.hide()
            self.app_gui.show_notification(
                "USB Security Scanner", 
                "Application is still running in the system tray."
            )
        else:
            # Show confirmation dialog
            reply = QMessageBox.question(
                self, "Exit Confirmation", 
                "Are you sure you want to exit the application?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                # Stop monitoring
                self.usb_monitor.stop_monitoring()
                # Accept the close event
                event.accept()
            else:
                event.ignore()


class ThreatDetailsDialog(QDialog):
    """Dialog to display detailed information about a detected threat."""
    
    def __init__(self, scan_result, parent=None):
        super().__init__(parent)
        self.scan_result = scan_result
        self.setWindowTitle(f"Threat Details: {scan_result.threat_name}")
        self.setMinimumSize(700, 500)
        
        self.layout = QVBoxLayout(self)
        
        # Header section
        header_frame = QFrame()
        header_frame.setFrameShape(QFrame.Shape.StyledPanel)
        header_layout = QVBoxLayout(header_frame)
        
        # Threat name in large font
        threat_name = QLabel(scan_result.threat_name)
        threat_name.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        header_layout.addWidget(threat_name)
        
        # Key threat information
        threat_info = QLabel(f"Type: {scan_result.threat_type.capitalize()}")
        threat_info.setFont(QFont("Arial", 12))
        header_layout.addWidget(threat_info)
        
        confidence = QLabel(f"Confidence: {scan_result.confidence}%")
        confidence.setFont(QFont("Arial", 12))
        header_layout.addWidget(confidence)
        
        self.layout.addWidget(header_frame)
        
        # File information section
        file_group = QGroupBox("File Information")
        file_layout = QFormLayout(file_group)
        
        file_layout.addRow("Path:", QLabel(scan_result.path))
        file_layout.addRow("Size:", QLabel(self._get_file_size(scan_result.path)))
        file_layout.addRow("Last Modified:", QLabel(self._get_last_modified(scan_result.path)))
        if 'file_type' in scan_result.details:
            file_layout.addRow("File Type:", QLabel(scan_result.details['file_type']))
        if 'mime_type' in scan_result.details:
            file_layout.addRow("MIME Type:", QLabel(scan_result.details['mime_type']))
        
        self.layout.addWidget(file_group)
        
        # Detection details section
        details_group = QGroupBox("Detection Details")
        details_layout = QVBoxLayout(details_group)
        
        details_text = QTextEdit()
        details_text.setReadOnly(True)
        
        # Format detection details in a readable way
        details_html = "<style>h3 { color: #003366; } .key { font-weight: bold; color: #333; } ul { margin-top: 2px; }</style>"
        
        # Add specific detection information based on what was found
        if 'known_malware' in scan_result.details:
            details_html += f"<h3>Known Malware</h3>"
            details_html += f"<p>This file matches a known malware signature: {scan_result.details['known_malware']}</p>"
        
        if 'clamav_detection' in scan_result.details:
            details_html += f"<h3>ClamAV Detection</h3>"
            details_html += f"<p>ClamAV detected: {scan_result.details['clamav_detection']}</p>"
        
        if 'yara_matches' in scan_result.details:
            details_html += f"<h3>YARA Rule Matches</h3>"
            details_html += "<ul>"
            for rule in scan_result.details['yara_matches']:
                details_html += f"<li>{rule}</li>"
            details_html += "</ul>"
        
        if 'virustotal' in scan_result.details:
            vt = scan_result.details['virustotal']
            details_html += f"<h3>VirusTotal Results</h3>"
            details_html += f"<p>{vt['positives']} of {vt['total']} antivirus engines detected this file as malicious.</p>"
            if 'permalink' in vt:
                details_html += f"<p>VirusTotal report: <a href='{vt['permalink']}'>{vt['permalink']}</a></p>"
        
        if 'pe_anomalies' in scan_result.details:
            details_html += f"<h3>PE File Anomalies</h3>"
            details_html += "<ul>"
            for anomaly in scan_result.details['pe_anomalies']:
                details_html += f"<li>{anomaly.replace('_', ' ').title()}</li>"
            details_html += "</ul>"
        
        if 'extension_mismatch' in scan_result.details:
            details_html += f"<h3>Extension Mismatch</h3>"
            details_html += f"<p>{scan_result.details['extension_mismatch']}</p>"
        
        if 'autorun_file' in scan_result.details:
            details_html += f"<h3>Autorun File</h3>"
            details_html += f"<p>This file is designed to run automatically when a drive is connected.</p>"
        
        if 'suspicious_patterns' in scan_result.details:
            details_html += f"<h3>Suspicious Patterns</h3>"
            details_html += "<ul>"
            for pattern in scan_result.details['suspicious_patterns'][:15]:  # Limit to 15 patterns to avoid overflow
                details_html += f"<li>{pattern}</li>"
            if len(scan_result.details['suspicious_patterns']) > 15:
                details_html += f"<li>...and {len(scan_result.details['suspicious_patterns']) - 15} more</li>"
            details_html += "</ul>"
        
        if 'archive_threats' in scan_result.details:
            details_html += f"<h3>Archive Contains Suspicious Files</h3>"
            details_html += "<ul>"
            for threat in scan_result.details['archive_threats']:
                details_html += f"<li>{threat}</li>"
            details_html += "</ul>"
        
        if 'high_entropy' in scan_result.details:
            details_html += f"<h3>High Entropy ({scan_result.details['high_entropy']:.2f})</h3>"
            details_html += f"<p>This file has unusually high entropy, which may indicate encryption, packing, or obfuscation.</p>"
        
        # If no specific details were found, show general information
        if len(details_html) < 100:
            details_html += "<p>Multiple suspicious indicators were found in this file.</p>"
        
        details_text.setHtml(details_html)
        details_layout.addWidget(details_text)
        
        self.layout.addWidget(details_group)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        quarantine_btn = QPushButton("Quarantine File")
        quarantine_btn.clicked.connect(self._quarantine_file)
        button_layout.addWidget(quarantine_btn)
        
        delete_btn = QPushButton("Delete File")
        delete_btn.clicked.connect(self._delete_file)
        button_layout.addWidget(delete_btn)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        button_layout.addWidget(close_btn)
        
        self.layout.addLayout(button_layout)
    
    def _quarantine_file(self):
        """Quarantine the threat file."""
        parent = self.parent()
        if parent and hasattr(parent, 'scan_engine'):
            success = parent.scan_engine.quarantine_file(self.scan_result.path)
            if success:
                parent.log_activity(f"Quarantined threat: {self.scan_result.path}")
                QMessageBox.information(
                    self, "File Quarantined", 
                    "The file has been moved to quarantine."
                )
                self.close()
                # Refresh quarantine tab
                if hasattr(parent, 'refresh_quarantine'):
                    parent.refresh_quarantine()
            else:
                QMessageBox.warning(
                    self, "Quarantine Failed", 
                    f"Failed to quarantine file: {self.scan_result.path}"
                )
    
    def _delete_file(self):
        """Delete the threat file."""
        reply = QMessageBox.question(
            self, "Confirm Deletion", 
            f"Are you sure you want to permanently delete this file?\n{self.scan_result.path}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                os.remove(self.scan_result.path)
                parent = self.parent()
                if parent:
                    parent.log_activity(f"Deleted threat: {self.scan_result.path}")
                QMessageBox.information(
                    self, "File Deleted", 
                    "The file has been deleted successfully."
                )
                self.close()
            except Exception as e:
                logger.error(f"Error deleting file {self.scan_result.path}: {e}", exc_info=True)
                QMessageBox.critical(
                    self, "Deletion Failed", 
                    f"Failed to delete file: {str(e)}"
                )
    
    def _get_file_size(self, file_path):
        """Get human-readable file size."""
        try:
            if os.path.exists(file_path):
                size = os.path.getsize(file_path)
                for unit in ['B', 'KB', 'MB', 'GB']:
                    if size < 1024.0:
                        return f"{size:.2f} {unit}"
                    size /= 1024.0
                return f"{size:.2f} TB"
            return "File not found"
        except:
            return "Unknown"
    
    def _get_last_modified(self, file_path):
        """Get the last modified date of the file."""
        try:
            if os.path.exists(file_path):
                mtime = os.path.getmtime(file_path)
                return datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
            return "File not found"
        except:
            return "Unknown" 