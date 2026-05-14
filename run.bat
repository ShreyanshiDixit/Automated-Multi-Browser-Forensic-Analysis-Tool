@echo off
title Browser Forensic Analysis Tool
echo.
echo  Browser Forensic Analysis Tool
echo  ================================
echo.

:: Check Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo  ERROR: Python is not installed or not in PATH.
    echo  Please install Python 3.8 or higher from https://python.org
    pause
    exit /b 1
)

:: Check if running as administrator (needed for live acquisition)
net session >nul 2>&1
if errorlevel 1 (
    echo  NOTE: Not running as Administrator.
    echo  Dead Acquisition will work normally.
    echo  Live Acquisition requires Administrator privileges.
    echo.
)

:: Create output directories if they don't exist
if not exist "output\artifacts" mkdir "output\artifacts"
if not exist "output\logs"      mkdir "output\logs"

echo  Starting server...
echo  Open your browser to: http://localhost:5000
echo  Press Ctrl+C to stop the tool.
echo.

cd /d "%~dp0"
python app.py
pause