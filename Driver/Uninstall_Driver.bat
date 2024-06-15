@echo off
setlocal

:: Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\icacls.exe" "%SYSTEMROOT%\system32\config\system"

if %errorlevel% NEQ 0 goto NoAdmin
goto gotAdmin

:NoAdmin
    echo You do not have administrator rights, please run this script as administrator.
    pause
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs"

sc stop PYAS_Driver
sc delete PYAS_Driver

bcdedit /set testsigning off
bcdedit -debug off

shutdown -r -t 0
endlocal