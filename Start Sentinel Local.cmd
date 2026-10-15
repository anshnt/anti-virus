@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if not errorlevel 1 (
    py -3 "%~dp0launch.py"
    goto :finish
)
where python >nul 2>&1
if errorlevel 1 (
    echo Install Python 3.11 or newer from https://www.python.org/downloads/windows/
    pause
    exit /b 1
)
python "%~dp0launch.py"
:finish
if errorlevel 1 pause
