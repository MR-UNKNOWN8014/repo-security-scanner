@echo off
echo ============================================================
echo   Dependency Installation for Repository Security Scanner
echo ============================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.8+
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

for /f "tokens=2" %%I in ('python --version 2^>^&1') do set PYTHON_VERSION=%%I
echo [OK] Python %PYTHON_VERSION% detected

for /f "tokens=1,2 delims=." %%a in ("%PYTHON_VERSION%") do (
    set PYTHON_MAJOR=%%a
    set PYTHON_MINOR=%%b
)

if %PYTHON_MAJOR% LSS 3 (
    echo [ERROR] Python 3 required
    pause
    exit /b 1
)

if %PYTHON_MINOR% LSS 8 (
    echo [ERROR] Python 3.8+ required. You have %PYTHON_VERSION%
    pause
    exit /b 1
)

echo.
echo Installing dependencies...
python -m pip install --upgrade pip >nul 2>&1
python -m pip install -r requirements.txt >nul 2>&1

if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

echo [OK] Installation complete
pause