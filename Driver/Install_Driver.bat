@echo off
setlocal

:: Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\icacls.exe" "%SYSTEMROOT%\system32\config\system"

if '%errorlevel%' NEQ '0' (goto UACPrompt) else (goto gotAdmin)

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0""", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )

set script_dir=%~dp0
set script_dir=%script_dir:~0,-1%
bcdedit -debug on
bcdedit /deletevalue {current} safeboot
bcdedit /set testsigning on
powershell.exe -ExecutionPolicy Bypass -Command ^
"$endDate = (Get-Date).AddYears(100); ^
 $cert = New-SelfSignedCertificate -DnsName PYAS -CertStoreLocation cert:\LocalMachine\My -Type CodeSigning -NotAfter $endDate; ^
 $pwd = ConvertTo-SecureString -String 'PYAS' -Force -AsPlainText; ^
 Export-PfxCertificate -Cert $cert -FilePath '%script_dir%\PYAS.pfx' -Password $pwd;"
"%script_dir%\signtool.exe" sign /f "%script_dir%\PYAS.pfx" /p PYAS "%script_dir%\PYAS_Driver.sys"
sc create PYAS_Driver type= kernel start= demand binPath= "%script_dir%\PYAS_Driver.sys"
shutdown -r -t 0

endlocal