@echo off
rem ThreatScanUSB Launcher
rem This batch file runs the USB Security Scanner from any location

echo Starting ThreatScanUSB Security Scanner...

rem Get the directory where this batch file is located
set APPDIR=%~dp0
cd /d "%APPDIR%"

rem Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python is not installed or not in the PATH.
    echo Please install Python 3.8 or later and try again.
    pause
    exit /b 1
)

rem Check if required libraries are installed
echo Checking required libraries...
pip show pywin32 >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Installing required libraries...
    pip install -r requirements.txt
    if %ERRORLEVEL% NEQ 0 (
        echo ERROR: Failed to install required libraries.
        echo Please run 'pip install -r requirements.txt' manually.
        pause
        exit /b 1
    )
)

rem Run the application
echo Starting ThreatScanUSB...
python run.py %*

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Application exited with code %ERRORLEVEL%
    pause
)

exit /b %ERRORLEVEL% 