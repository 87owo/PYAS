#define AppId "{{a7d7bac3-93b8-4630-8308-c7a56bf7fdf4}"
#define AppName "PYAS"
#define AppVersion "3.5.9.0"
#define AppPublisher "PYAS Security"
#define AppURL "https://github.com/87owo/PYAS"
#define AppExeName "PYAS.exe"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Setup
VersionInfoProductName={#AppName} Setup
VersionInfoProductVersion={#AppVersion}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppPublisher}\{#AppName}
AllowNoIcons=yes
LicenseFile=SetupResources\licence.rtf
ShowLanguageDialog=yes
WizardStyle=modern
WizardImageFile=SetupResources\wizardImage.bmp
WizardSmallImageFile=SetupResources\headerImage.png
SetupIconFile=Payload\Interface\static\img\icon.ico
UninstallDisplayIcon={app}\{#AppExeName}
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
Compression=lzma2/max
SolidCompression=yes
OutputDir=Output
OutputBaseFilename=PYAS_Setup
UsePreviousTasks=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "chinesesimplified"; MessagesFile: "SetupResources\ChineseSimplified.isl"
Name: "chinesetraditional"; MessagesFile: "SetupResources\ChineseTraditional.isl"
Name: "japanese"; MessagesFile: "SetupResources\Japanese.isl"
Name: "korean"; MessagesFile: "SetupResources\Korean.isl"
Name: "french"; MessagesFile: "SetupResources\French.isl"
Name: "spanish"; MessagesFile: "SetupResources\Spanish.isl"
Name: "hindi"; MessagesFile: "SetupResources\Hindi.isl"
Name: "arabic"; MessagesFile: "SetupResources\Arabic.isl"
Name: "russian"; MessagesFile: "SetupResources\Russian.isl"
Name: "slovenian"; MessagesFile: "SetupResources\Slovenian.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "autostart"; Description: "{cm:AutoStartTask}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "install_webview2"; Description: "{cm:InstallWebView2}"; GroupDescription: "{cm:Dependencies}"
Name: "install_vcredist"; Description: "{cm:InstallVCRedist}"; GroupDescription: "{cm:Dependencies}"

[Files]
Source: "Payload\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Redist\VC_redist.x64.exe"; DestDir: "{tmp}\PYAS_Redist"; Flags: deleteafterinstall ignoreversion
Source: "Redist\MicrosoftEdgeWebview2Setup.exe"; DestDir: "{tmp}\PYAS_Redist"; Flags: deleteafterinstall ignoreversion

[Registry]
Root: HKCU; Subkey: "Software\Classes\*\shell\PYAS_Scan"; Flags: uninsdeletekey dontcreatekey
Root: HKCU; Subkey: "Software\Classes\Directory\shell\PYAS_Scan"; Flags: uninsdeletekey dontcreatekey

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\PYAS"

[Icons]
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"

[Run]
Filename: "{tmp}\PYAS_Redist\VC_redist.x64.exe"; Parameters: "/quiet /norestart"; Flags: waituntilterminated runhidden; StatusMsg: "{cm:InstallingVCRuntime}"; Tasks: install_vcredist
Filename: "{tmp}\PYAS_Redist\MicrosoftEdgeWebview2Setup.exe"; Parameters: "/silent /install"; Flags: waituntilterminated runhidden; StatusMsg: "{cm:InstallingWebView2Runtime}"; Tasks: install_webview2
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runascurrentuser

[CustomMessages]
english.InstallingVCRuntime=Installing Microsoft Visual C++ Runtime...
chinesesimplified.InstallingVCRuntime=正在安装 Microsoft Visual C++ 运行库...
chinesetraditional.InstallingVCRuntime=正在安裝 Microsoft Visual C++ 執行庫...
english.InstallingWebView2Runtime=Installing Microsoft Edge WebView2 Runtime...
chinesesimplified.InstallingWebView2Runtime=正在安装 Microsoft Edge WebView2 Runtime...
chinesetraditional.InstallingWebView2Runtime=正在安裝 Microsoft Edge WebView2 Runtime...
english.AutoStartTask=Run PYAS automatically at system startup
chinesesimplified.AutoStartTask=开机时自动运行 PYAS
chinesetraditional.AutoStartTask=開機時自動執行 PYAS
english.Dependencies=Dependencies:
chinesesimplified.Dependencies=运行环境:
chinesetraditional.Dependencies=執行環境:
english.InstallWebView2=Install Microsoft Edge WebView2 Runtime
chinesesimplified.InstallWebView2=安装 Microsoft Edge WebView2 运行环境
chinesetraditional.InstallWebView2=安裝 Microsoft Edge WebView2 執行環境
english.InstallVCRedist=Install Microsoft Visual C++ Runtime
chinesesimplified.InstallVCRedist=安装 Microsoft Visual C++ 运行库
chinesetraditional.InstallVCRedist=安裝 Microsoft Visual C++ 執行庫
english.LegacyVersionDetected=An older version of PYAS was detected. Please uninstall it manually before installing.
chinesesimplified.LegacyVersionDetected=检测到存在旧版 PYAS。请先手动卸载旧版后，再运行本安装程序。
chinesetraditional.LegacyVersionDetected=檢測到存在舊版 PYAS。請先手動卸載舊版後，再執行本安裝程式。

[Code]
var
  TasksInitialized: Boolean;

function IsWebView2Installed: Boolean;
var
  RegKeyPath: string;
  Version: string;
begin
  RegKeyPath := 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';
  Result := False;
  if RegQueryStringValue(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version) then
    if Length(Version) > 0 then Result := True;
  if not Result and RegQueryStringValue(HKCU, RegKeyPath, 'pv', Version) then
    if Length(Version) > 0 then Result := True;
  if not Result and RegQueryStringValue(HKLM, RegKeyPath, 'pv', Version) then
    if Length(Version) > 0 then Result := True;
end;

function IsVCRedistInstalled: Boolean;
var
  Bld: Cardinal;
begin
  Result := False;
  if RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Bld', Bld) then
    if Bld > 0 then Result := True;
end;

procedure CurPageChanged(CurPageID: Integer);
var
  I: Integer;
  ItemText: string;
begin
  if (CurPageID = wpSelectTasks) and not TasksInitialized then
  begin
    TasksInitialized := True;
    for I := 0 to WizardForm.TasksList.Items.Count - 1 do
    begin
      ItemText := WizardForm.TasksList.Items[I];
      if Pos('Visual C++', ItemText) > 0 then
        WizardForm.TasksList.Checked[I] := not IsVCRedistInstalled
      else if Pos('WebView2', ItemText) > 0 then
        WizardForm.TasksList.Checked[I] := not IsWebView2Installed;
    end;
  end;
end;

procedure QuitOldInstance(InstallPath: string);
var
  ResultCode: Integer;
  ExePath: string;
begin
  ExePath := InstallPath + '\{#AppExeName}';
  if FileExists(ExePath) then
  begin
    Exec(ExePath, '-quit', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(500);
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExeName} /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

function InitializeSetup(): Boolean;
var
  OldInstallPath: string;
  LegacyPath: string;
begin
  LegacyPath := ExpandConstant('{pf32}\{#AppName}');
  if DirExists(LegacyPath) and FileExists(LegacyPath + '\{#AppExeName}') then
  begin
    MsgBox(CustomMessage('LegacyVersionDetected'), mbCriticalError, MB_OK);
    Result := False;
    Exit;
  end;
  if RegQueryStringValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' + ExpandConstant('{#AppId}') + '_is1', 'InstallLocation', OldInstallPath) or
     RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' + ExpandConstant('{#AppId}') + '_is1', 'InstallLocation', OldInstallPath) then
  begin
    QuitOldInstance(OldInstallPath);
  end;
  
  Result := True;
end;

function InitializeUninstall(): Boolean;
begin
  QuitOldInstance(ExpandConstant('{app}'));
  Result := True;
end;

procedure TryCreateStartupTask;
var
  ResultCode: Integer;
  PSExe: string;
  PSCommand: string;
  AppPath: string;
begin
  AppPath := ExpandConstant('{app}\{#AppExeName}');
  PSExe := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  PSCommand := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Command ' +
               '$Action = New-ScheduledTaskAction -Execute ''' + AppPath + ''' -Argument ''-hide''; ' +
               '$Trigger = New-ScheduledTaskTrigger -AtLogOn; ' +
               '$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; ' +
               'Register-ScheduledTask -TaskName ''PYAS_Security_ATS'' -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel Highest -Force';
  if not Exec(PSExe, PSCommand, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Log(Format('Failed to create scheduled task, Exec error code: %d', [ResultCode]));
  end
  else if ResultCode <> 0 then
  begin
    Log(Format('powershell returned exit code %d while creating the scheduled task', [ResultCode]));
  end;
end;

procedure TryDeleteStartupTask;
var
  ResultCode: Integer;
begin
  if not Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /TN "PYAS_Security_ATS" /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Log(Format('Failed to delete scheduled task, Exec error code: %d', [ResultCode]));
  end
  else if ResultCode <> 0 then
  begin
    Log(Format('schtasks returned exit code %d while deleting the scheduled task', [ResultCode]));
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('autostart') then
    begin
      TryCreateStartupTask;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    TryDeleteStartupTask;
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    DelTree(ExpandConstant('{app}'), True, True, True);
  end;
end;