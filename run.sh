#!/bin/bash
# ThreatScanUSB Launcher
# This shell script runs the USB Security Scanner from any location

echo "Starting ThreatScanUSB Security Scanner..."

# Get the directory where this script is located
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
cd "$SCRIPT_DIR"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed or not in the PATH."
    echo "Please install Python 3.8 or later and try again."
    read -p "Press Enter to exit..."
    exit 1
fi

# Check if required libraries are installed
echo "Checking required libraries..."
if ! python3 -c "import win32api" &> /dev/null; then
    echo "Installing required libraries..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install required libraries."
        echo "Please run 'pip3 install -r requirements.txt' manually."
        read -p "Press Enter to exit..."
        exit 1
    fi
fi

# Run the application
echo "Starting ThreatScanUSB..."
python3 run.py "$@"

if [ $? -ne 0 ]; then
    echo "ERROR: Application exited with code $?"
    read -p "Press Enter to exit..."
fi

exit $? 