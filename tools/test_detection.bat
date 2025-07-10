@echo off
rem Detection Test Tool Launcher
rem Run this batch file to test detection capabilities

echo ===== ThreatScanUSB Detection Test Tool =====

rem Get the directory where this batch file is located
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%.."

rem Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python is not installed or not in the PATH.
    echo Please install Python 3.8 or later and try again.
    pause
    exit /b 1
)

rem Run the test script
echo Running detection test...
python tools/test_detection.py

pause 