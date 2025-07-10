#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Detection Test Tool

This script tests the detection capabilities of the ThreatScanUsb scanner
by scanning the test samples directory and reporting the results.
"""

import os
import sys
import time
import logging
from pathlib import Path

# Add the parent directory to the path to import scanner modules
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

# Import scanner modules
from src.config import load_configuration, set_app_directory
from src.scanner import ScanEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('ThreatScanUsb.TestTool')

def test_detection():
    """Test the scanner's detection capabilities on test samples."""
    print("\n===== ThreatScanUsb Detection Test Tool =====\n")
    
    # Set application directory
    app_dir = parent_dir
    set_app_directory(app_dir)
    
    # Load configuration
    config = load_configuration()
    
    # Create scanner engine
    print("Initializing scanner engine...")
    scanner = ScanEngine(config)
    
    # Define test directory
    test_dir = os.path.join(app_dir, 'resources', 'test_samples')
    if not os.path.exists(test_dir):
        print(f"ERROR: Test samples directory not found at {test_dir}")
        return
    
    # List test samples
    test_files = [f for f in os.listdir(test_dir) if os.path.isfile(os.path.join(test_dir, f))]
    if not test_files:
        print("No test files found in the test samples directory.")
        return
    
    print(f"Found {len(test_files)} test files:")
    for file in test_files:
        print(f"  - {file}")
    
    print("\nTesting scanner detection capabilities...")
    print("=" * 60)
    
    # Test each file individually
    results = []
    for file in test_files:
        file_path = os.path.join(test_dir, file)
        
        print(f"\nScanning: {file}")
        print("-" * 40)
        
        start_time = time.time()
        result = scanner._scan_file(file_path)
        scan_time = time.time() - start_time
        
        if result and result.is_threat:
            print(f"✅ DETECTED as {result.threat_type}: {result.threat_name}")
            print(f"   Confidence: {result.confidence}%")
            print(f"   Scan time: {scan_time:.3f} seconds")
            
            # Show detection details
            if result.details:
                print("\n   Detection details:")
                for key, value in result.details.items():
                    if key == 'suspicious_patterns' and isinstance(value, list):
                        print(f"     - {key}: {len(value)} patterns found")
                        # Show a few example patterns
                        for pattern in value[:5]:
                            print(f"       * {pattern}")
                        if len(value) > 5:
                            print(f"       * ... and {len(value) - 5} more")
                    else:
                        print(f"     - {key}: {value}")
            
            results.append((file, True, result.threat_name, result.confidence))
        else:
            print(f"❌ NOT DETECTED as a threat")
            print(f"   Scan time: {scan_time:.3f} seconds")
            results.append((file, False, None, 0))
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY:")
    print("=" * 60)
    
    detection_count = sum(1 for _, detected, _, _ in results if detected)
    print(f"Total files tested: {len(results)}")
    print(f"Files detected: {detection_count}")
    print(f"Detection rate: {detection_count / len(results) * 100:.1f}%")
    
    if detection_count < len(results):
        print("\nFiles NOT detected:")
        for file, detected, _, _ in results:
            if not detected:
                print(f"  - {file}")
    
    print("\nTest complete!")

if __name__ == "__main__":
    test_detection() 