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

set "script_dir=%~dp0"
set "script_dir=%script_dir:~0,-1%"

bcdedit -debug on
bcdedit /set testsigning on
bcdedit /deletevalue {current} safeboot

powershell.exe -ExecutionPolicy Bypass -Command ^
"$endDate = (Get-Date).AddYears(100); ^
 $cert = New-SelfSignedCertificate -DnsName PYAS -CertStoreLocation cert:\LocalMachine\My -Type CodeSigning -NotAfter $endDate; ^
 $pwd = ConvertTo-SecureString -String 'PYAS' -Force -AsPlainText; ^
 Export-PfxCertificate -Cert $cert -FilePath '%script_dir%\PYAS.pfx' -Password $pwd;"
"%script_dir%\signtool.exe" sign /f "%script_dir%\PYAS.pfx" /p PYAS "%script_dir%\PYAS_Driver.sys"
sc create PYAS_Driver type= kernel start= demand binPath= "%script_dir%\PYAS_Driver.sys"

shutdown -r -t 0
endlocal