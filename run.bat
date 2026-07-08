@echo off
setlocal EnableDelayedExpansion

cd /d "%~dp0"

echo ============================================
echo Generic Domain Certificate Finder
echo ============================================
echo.

set /p TARGET_DOMAIN=Enter the domain to search for, example example.com: 

if "%TARGET_DOMAIN%"=="" (
    echo.
    echo [!] No domain entered. Exiting.
    pause
    exit /b 1
)

if not exist "reports_output" mkdir "reports_output"

:MENU
cls
echo ============================================
echo Generic Domain Certificate Finder
echo Target Domain: %TARGET_DOMAIN%
echo Output Folder: reports_output
echo ============================================
echo.
echo 1. Find certificates/domains for %TARGET_DOMAIN%
echo 2. Probe discovered non-prod domains
echo 3. Generate CSV reports
echo 4. Full workflow: find, probe, and report
echo 5. Show status
echo 6. Change target domain
echo 7. Exit
echo.

set /p MENU_CHOICE=Choose an option [1-7]: 

if "%MENU_CHOICE%"=="1" goto SEED
if "%MENU_CHOICE%"=="2" goto PROBE
if "%MENU_CHOICE%"=="3" goto REPORTS
if "%MENU_CHOICE%"=="4" goto ALL
if "%MENU_CHOICE%"=="5" goto STATUS
if "%MENU_CHOICE%"=="6" goto CHANGE_DOMAIN
if "%MENU_CHOICE%"=="7" goto END

echo.
echo [!] Invalid option.
pause
goto MENU

:SEED
echo.
if not exist "reports_output" mkdir "reports_output"
echo [+] Finding certificates/domains for %TARGET_DOMAIN% using all CT/passive sources
python main.py seed-domain %TARGET_DOMAIN%
echo.
echo [+] Current reports_output files:
dir reports_output
pause
goto MENU

:PROBE
echo.
if not exist "reports_output" mkdir "reports_output"
echo [+] Probing discovered non-prod domains
python main.py probe
echo.
echo [+] Current reports_output files:
dir reports_output
pause
goto MENU

:REPORTS
echo.
if not exist "reports_output" mkdir "reports_output"
echo [+] Generating reports for %TARGET_DOMAIN%
python main.py report %TARGET_DOMAIN%
echo.
echo [+] Current reports_output files:
dir reports_output
pause
goto MENU

:ALL
echo.
if not exist "reports_output" mkdir "reports_output"

echo [+] Finding certificates/domains for %TARGET_DOMAIN% using all CT/passive sources
python main.py seed-domain %TARGET_DOMAIN%

echo.
echo [+] Probing discovered non-prod domains
python main.py probe

echo.
echo [+] Generating reports for %TARGET_DOMAIN%
python main.py report %TARGET_DOMAIN%

echo.
echo [+] Done. Check the reports_output folder.
dir reports_output
pause
goto MENU

:STATUS
echo.
python main.py status
pause
goto MENU

:CHANGE_DOMAIN
echo.
set /p NEW_TARGET_DOMAIN=Enter the new domain to search for, example example.com: 
if not "%NEW_TARGET_DOMAIN%"=="" (
    set TARGET_DOMAIN=%NEW_TARGET_DOMAIN%
)
goto MENU

:END
echo.
echo Goodbye.
endlocal
exit /b 0
