#define AppId "{{a7d7bac3-93b8-4630-8308-c7a56bf7fdf4}"
#define AppName "PYAS"
#define AppVersion "3.6.5.0"
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

[Files]
Source: "Redist\VC_redist.x64.exe"; DestDir: "{tmp}\PYAS_Redist"; Flags: deleteafterinstall ignoreversion; AfterInstall: EnsureVCRedist
Source: "Redist\MicrosoftEdgeWebview2Setup.exe"; DestDir: "{tmp}\PYAS_Redist"; Flags: deleteafterinstall ignoreversion; AfterInstall: EnsureWebView2
Source: "Payload\Engine\*"; DestDir: "{app}\Engine"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Payload\Interface\*"; DestDir: "{app}\Interface"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Payload\License\*"; DestDir: "{app}\License"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Payload\PYAS.exe"; DestDir: "{app}"; Flags: ignoreversion; AfterInstall: FinalizeDriverRemoval
Source: "Payload\Plugins\*"; DestDir: "{app}\Plugins"; Flags: ignoreversion recursesubdirs createallsubdirs

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
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runascurrentuser; Check: CanLaunchApp

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
english.QuitFailed=PYAS or its driver could not be stopped safely. Restart Windows and run Setup again.
english.DependencyInstallFailed=Required Microsoft runtime installation failed. Setup cannot continue.
chinesesimplified.LegacyVersionDetected=检测到存在旧版 PYAS。请先手动卸载旧版后，再运行本安装程序。
chinesetraditional.LegacyVersionDetected=檢測到存在舊版 PYAS。請先手動卸載舊版後，再執行本安裝程式。

[Code]
var
  DependencyRestartRequired: Boolean;
  DependenciesReady: Boolean;

function FindWindow(lpClassName: LongWord; lpWindowName: string): HWND;
  external 'FindWindowW@user32.dll stdcall';

function GetTickCount: Cardinal;
  external 'GetTickCount@kernel32.dll stdcall';

function IsValidRuntimeVersion(Version: string): Boolean;
begin
  Result := (Length(Trim(Version)) > 0) and (Trim(Version) <> '0.0.0.0');
end;

function IsWebView2Installed: Boolean;
var
  Version: string;
begin
  Result := False;
  if RegQueryStringValue(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version) then
    Result := IsValidRuntimeVersion(Version);
  if not Result and RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version) then
    Result := IsValidRuntimeVersion(Version);
  if not Result and RegQueryStringValue(HKCU, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version) then
    Result := IsValidRuntimeVersion(Version);
end;

function IsVCRedistInstalled: Boolean;
var
  Installed: Cardinal;
  Version: string;
begin
  Result := False;
  if RegQueryDWordValue(HKLM64, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Installed', Installed) and (Installed = 1) then
  begin
    if RegQueryStringValue(HKLM64, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Version', Version) then
      Result := IsValidRuntimeVersion(Version)
    else
      Result := True;
  end;
end;

function DependencyExitCodeSucceeded(ResultCode: Integer): Boolean;
begin
  Result := (ResultCode = 0) or (ResultCode = 1641) or (ResultCode = 3010);
  if (ResultCode = 1641) or (ResultCode = 3010) then
    DependencyRestartRequired := True;
end;

procedure EnsureVCRedist;
var
  ResultCode: Integer;
  InstallerPath: string;
begin
  if IsVCRedistInstalled then Exit;
  InstallerPath := ExpandConstant('{tmp}\PYAS_Redist\VC_redist.x64.exe');
  WizardForm.StatusLabel.Caption := CustomMessage('InstallingVCRuntime');
  if not Exec(InstallerPath, '/quiet /norestart', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or
     not DependencyExitCodeSucceeded(ResultCode) or not IsVCRedistInstalled then
  begin
    DependenciesReady := False;
    RaiseException(CustomMessage('DependencyInstallFailed'));
  end;
end;

procedure EnsureWebView2;
var
  ResultCode: Integer;
  InstallerPath: string;
begin
  if IsWebView2Installed then Exit;
  InstallerPath := ExpandConstant('{tmp}\PYAS_Redist\MicrosoftEdgeWebview2Setup.exe');
  WizardForm.StatusLabel.Caption := CustomMessage('InstallingWebView2Runtime');
  if not Exec(InstallerPath, '/silent /install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or
     not DependencyExitCodeSucceeded(ResultCode) or not IsWebView2Installed then
  begin
    DependenciesReady := False;
    RaiseException(CustomMessage('DependencyInstallFailed'));
  end;
end;

function WaitForMainWindowToClose(TimeoutMs: Cardinal): Boolean;
var
  Deadline: Cardinal;
begin
  Deadline := GetTickCount + TimeoutMs;
  repeat
    if FindWindow(0, 'PYAS Security') = 0 then
    begin
      Result := True;
      Exit;
    end;
    Sleep(100);
  until GetTickCount >= Deadline;
  Result := False;
end;

function QuitOldInstance(InstallPath: string): Boolean;
var
  ResultCode: Integer;
  ExePath: string;
begin
  Result := True;
  ExePath := InstallPath + '\{#AppExeName}';
  if not FileExists(ExePath) then Exit;

  if not Exec(ExePath, '-quit', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Result := False;
    Exit;
  end;

  Result := (ResultCode = 0) and WaitForMainWindowToClose(30000);
end;

procedure FinalizeDriverRemoval;
var
  ResultCode: Integer;
  ExePath: string;
begin
  ExePath := ExpandConstant('{app}\{#AppExeName}');
  if not Exec(ExePath, '-quit', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
    RaiseException(CustomMessage('QuitFailed'));
end;

function InitializeSetup(): Boolean;
var
  OldInstallPath: string;
  LegacyPath: string;
begin
  DependencyRestartRequired := False;
  DependenciesReady := True;
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
    if not QuitOldInstance(OldInstallPath) then
    begin
      MsgBox(CustomMessage('QuitFailed'), mbCriticalError, MB_OK);
      Result := False;
      Exit;
    end;
  end;

  Result := True;
end;

function InitializeUninstall(): Boolean;
begin
  Result := QuitOldInstance(ExpandConstant('{app}'));
  if not Result then
    MsgBox(CustomMessage('QuitFailed'), mbCriticalError, MB_OK);
end;

function CanLaunchApp: Boolean;
begin
  Result := DependenciesReady and not DependencyRestartRequired;
end;

function NeedRestart: Boolean;
begin
  Result := DependencyRestartRequired;
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