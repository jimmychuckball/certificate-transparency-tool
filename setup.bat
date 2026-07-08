@echo off
setlocal
echo.
echo  ============================================================
echo   Generic Certificate Monitor -- Setup
echo  ============================================================
echo.

:: Check Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo  ERROR: Python not found.
    echo  Install Python 3.9+ from https://www.python.org/downloads/
    echo  Make sure to tick "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo  Found: %PYVER%
echo.

:: Install dependencies
echo  Installing dependencies...
python -m pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo.
    echo  ERROR: pip install failed. Check your internet connection and try again.
    pause
    exit /b 1
)

echo.
echo  ============================================================
echo   Setup complete!
echo  ============================================================
echo.
echo  NEXT STEPS:
echo.
echo  Option A  -- Corporate laptop (has CT log access + existing domain file):
echo    python main.py bootstrap domains_file.txt
echo    python main.py scan
echo    python main.py export-domains
echo.
echo  Option B  -- Off-band laptop (external internet view):
echo    python main.py bootstrap nonprod_domains.txt
echo    python main.py probe
echo    python main.py report
echo.
echo  Option C  -- Full pipeline (scan + probe + report):
echo    python main.py run
echo.
pause
