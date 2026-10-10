#define AppId "{{a7d7bac3-93b8-4630-8308-c7a56bf7fdf4}"
#define AppName "PYAS"
#define AppVersion "3.7.1.0"
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
SetupLogging=yes
CloseApplications=no
RestartApplications=no

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

[Files]
Source: "Redist\VC_redist.x64.exe"; DestDir: "{tmp}\PYAS_Redist"; Flags: deleteafterinstall ignoreversion; AfterInstall: EnsureVCRedist
Source: "Redist\MicrosoftEdgeWebview2Setup.exe"; Flags: dontcopy noencryption
Source: "Payload\Engine\*"; DestDir: "{app}\Engine"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Payload\Interface\*"; DestDir: "{app}\Interface"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Payload\License\*"; DestDir: "{app}\License"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Payload\PYAS.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "Payload\Plugins\*"; DestDir: "{app}\Plugins"; Flags: ignoreversion recursesubdirs createallsubdirs

[Registry]
Root: HKCU; Subkey: "Software\Classes\*\shell\PYAS_Scan"; Flags: uninsdeletekey dontcreatekey
Root: HKCU; Subkey: "Software\Classes\Directory\shell\PYAS_Scan"; Flags: uninsdeletekey dontcreatekey
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "PYAS_Security"; Flags: uninsdeletevalue dontcreatekey

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
english.QuitFailed=PYAS is still running or did not respond to the exit request. Exit PYAS from its tray menu, then retry Setup.
chinesesimplified.QuitFailed=PYAS 仍在运行或未响应退出请求。请从托盘菜单退出 PYAS，然后重试安装。
chinesetraditional.QuitFailed=PYAS 仍在運作或未回應退出請求。請從系統匣選單退出 PYAS，再重試安裝。
english.DependencyInstallFailed=Required Microsoft runtime installation failed. Setup cannot continue.
english.WebView2InstallFailed=Microsoft Edge WebView2 Runtime could not be detected. Check your connection or install the Evergreen Runtime manually, then retry Setup.%n%nDetails: %1
chinesesimplified.WebView2InstallFailed=无法检测到 Microsoft Edge WebView2 运行环境。请检查网络或手动安装 Evergreen 运行环境，然后重试安装。%n%n详细信息：%1
chinesetraditional.WebView2InstallFailed=無法偵測到 Microsoft Edge WebView2 執行環境。請檢查網路或手動安裝 Evergreen 執行環境，再重試安裝。%n%n詳細資訊：%1
chinesesimplified.LegacyVersionDetected=检测到存在旧版 PYAS。请先手动卸载旧版后，再运行本安装程序。
chinesetraditional.LegacyVersionDetected=檢測到存在舊版 PYAS。請先手動卸載舊版後，再執行本安裝程式。

[Code]
var
  DependencyRestartRequired: Boolean;
  DependenciesReady: Boolean;

function GetWindowThreadProcessId(Wnd: HWND; var ProcessId: Cardinal): Cardinal;
  external 'GetWindowThreadProcessId@user32.dll stdcall';

function OpenProcess(Access: Cardinal; InheritHandle: Boolean; ProcessId: Cardinal): THandle;
  external 'OpenProcess@kernel32.dll stdcall';

function WaitForSingleObject(Handle: THandle; Timeout: Cardinal): Cardinal;
  external 'WaitForSingleObject@kernel32.dll stdcall';

function CloseHandle(Handle: THandle): Boolean;
  external 'CloseHandle@kernel32.dll stdcall';

function SendMessageTimeout(Wnd: HWND; Msg: Cardinal; WParam, LParam: Longint;
  Flags, Timeout: Cardinal; var MessageResult: LongWord): Longint;
  external 'SendMessageTimeoutW@user32.dll stdcall';

function GetTickCount: Cardinal;
  external 'GetTickCount@kernel32.dll stdcall';

function IsValidRuntimeVersion(Version: string): Boolean;
begin
  Result := (Length(Trim(Version)) > 0) and (Trim(Version) <> '0.0.0.0');
end;

function QueryWebView2Version(RootKey: Integer; RootName: string; LogDetails: Boolean): Boolean;
var
  Version: string;
  PackedVersion: Int64;
begin
  Result := False;
  if RegQueryStringValue(RootKey, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version) then
  begin
    if StrToVersion(Trim(Version), PackedVersion) then
      Result := PackedVersion > 0;
    if LogDetails or Result then
      Log('WebView2 ' + RootName + ': pv=' + Version + ', valid=' + IntToStr(Ord(Result)));
  end
  else if LogDetails then
    Log('WebView2 ' + RootName + ': version not found or not readable');
end;

function IsWebView2Installed(LogDetails: Boolean): Boolean;
begin
  Result := QueryWebView2Version(HKLM32, 'HKLM32', LogDetails);
  if not Result and IsWin64 then
    Result := QueryWebView2Version(HKLM64, 'HKLM64', LogDetails);
  if not Result then
    Result := QueryWebView2Version(HKCU32, 'HKCU32', LogDetails);
  if not Result and IsWin64 then
    Result := QueryWebView2Version(HKCU64, 'HKCU64', LogDetails);
end;

function WaitForWebView2: Boolean;
var
  Attempt: Integer;
begin
  for Attempt := 0 to 60 do
  begin
    Result := IsWebView2Installed(False);
    if Result then Exit;
    if Attempt < 60 then Sleep(500);
  end;
  Result := False;
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

function EnsureWebView2: string;
var
  ResultCode: Integer;
  InstallerPath, Detail: string;
  Started: Boolean;
begin
  Result := '';
  if IsWebView2Installed(True) then
  begin
    Log('WebView2 is already installed; skipping the bootstrapper');
    Exit;
  end;
  WizardForm.PreparingLabel.Caption := CustomMessage('InstallingWebView2Runtime');
  ExtractTemporaryFile('MicrosoftEdgeWebview2Setup.exe');
  InstallerPath := ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe');
  Log('Starting WebView2 bootstrapper: ' + InstallerPath + ' /silent /install');
  ResultCode := -1;
  Started := Exec(InstallerPath, '/silent /install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if Started then
  begin
    Detail := Format('WebView2 installer exit code: %d (0x%x)', [ResultCode, ResultCode]);
    if not DependencyExitCodeSucceeded(ResultCode) then
      Log('WebView2 installer returned a non-success code; checking the runtime before failing');
  end
  else
    Detail := Format('WebView2 installer launch error: %d (%s)', [ResultCode, SysErrorMessage(ResultCode)]);
  Log(Detail);
  if IsWebView2Installed(True) then
  begin
    Log('WebView2 was detected after the installation attempt; continuing Setup');
    Exit;
  end;
  if Started then
  begin
    Log('Waiting up to 30 seconds for WebView2 registration');
    if WaitForWebView2 then
    begin
      Log('WebView2 registration completed; continuing Setup');
      Exit;
    end;
  end;
  IsWebView2Installed(True);
  Log('WebView2 prerequisite failed: ' + Detail);
  Result := FmtMessage(CustomMessage('WebView2InstallFailed'), [Detail]);
end;

function QuitRunningInstance: Boolean;
var
  Wnd: HWND;
  ProcessId, Started, WaitResult: Cardinal;
  ProcessHandle: THandle;
  MessageResult: LongWord;
begin
  Result := True;
  Started := GetTickCount;
  repeat
    Wnd := FindWindowByWindowName('PYAS Security');
    if Wnd <> 0 then Break;
    if not CheckForMutexes('PYAS_Security_Mutex,PYAS_Security_Recovery_Mutex') then
    begin
      Log('PYAS is not running; no exit request is needed');
      Exit;
    end;
    Sleep(100);
  until GetTickCount - Started >= 10000;

  Result := False;
  if Wnd = 0 then
  begin
    Log('PYAS is running but its exit message window is not available');
    Exit;
  end;

  ProcessId := 0;
  GetWindowThreadProcessId(Wnd, ProcessId);
  if ProcessId = 0 then
  begin
    Result := FindWindowByWindowName('PYAS Security') = 0;
    Exit;
  end;

  ProcessHandle := OpenProcess($00100000, False, ProcessId);
  if ProcessHandle = 0 then
  begin
    Result := (FindWindowByWindowName('PYAS Security') = 0) and
      not CheckForMutexes('PYAS_Security_Mutex,PYAS_Security_Recovery_Mutex');
    Log('Could not open the PYAS process for exit monitoring');
    Exit;
  end;

  try
    if WaitForSingleObject(ProcessHandle, 0) = 0 then
    begin
      Result := True;
      Exit;
    end;

    Log('Sending an exit request to PYAS; the application owns driver shutdown');
    MessageResult := 0;
    if SendMessageTimeout(Wnd, $8501, 4, 0, $0022, 5000, MessageResult) = 0 then
      Log('PYAS exit message delivery failed or timed out')
    else if MessageResult <> 1 then
      Log('PYAS rejected the exit request; its maintenance channel may not be ready')
    else
      Log('PYAS accepted the exit request; waiting for process termination');

    Started := GetTickCount;
    repeat
      WaitResult := WaitForSingleObject(ProcessHandle, 0);
      if WaitResult = 0 then
      begin
        Result := (FindWindowByWindowName('PYAS Security') = 0) and
          not CheckForMutexes('PYAS_Security_Mutex,PYAS_Security_Recovery_Mutex');
        if Result then Log('PYAS process exited');
        Exit;
      end;
      if WaitResult <> $00000102 then
      begin
        Log('PYAS process exit monitoring failed');
        Exit;
      end;
      Sleep(100);
    until GetTickCount - Started >= 30000;
    Log('PYAS is still running after the exit request');
  finally
    CloseHandle(ProcessHandle);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): string;
begin
  DependenciesReady := False;
  NeedsRestart := DependencyRestartRequired;
  if not QuitRunningInstance then
  begin
    Result := CustomMessage('QuitFailed');
    Exit;
  end;
  try
    Result := EnsureWebView2;
  except
    Log('WebView2 prerequisite exception: ' + GetExceptionMessage);
    Result := FmtMessage(CustomMessage('WebView2InstallFailed'), [GetExceptionMessage]);
  end;
  DependenciesReady := Result = '';
  NeedsRestart := DependencyRestartRequired;
end;

function InitializeSetup(): Boolean;
var
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

  Result := QuitRunningInstance;
  if not Result then
    MsgBox(CustomMessage('QuitFailed'), mbCriticalError, MB_OK);
end;

function InitializeUninstall(): Boolean;
begin
  Result := QuitRunningInstance;
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
procedure RemoveLegacyStartupTask;
var
  TaskService: Variant;
  RootFolder: Variant;
begin
  try
    TaskService := CreateOleObject('Schedule.Service');
    TaskService.Connect();
    RootFolder := TaskService.GetFolder('\');
    try
      RootFolder.DeleteTask('PYAS_Security_ATS', 0);
      Log('Removed legacy PYAS scheduled startup task');
    except
      Log('Legacy PYAS scheduled startup task was not present or could not be removed');
    end;
  except
    Log('Task Scheduler COM was unavailable while cleaning the legacy startup task');
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    RemoveLegacyStartupTask;
  end;
end;

procedure RemoveStartupTasks;
var
  TaskService, RootFolder, Tasks, Task: Variant;
  I: Integer;
  TaskName, ExecutablePath: string;
begin
  try
    TaskService := CreateOleObject('Schedule.Service');
    TaskService.Connect();
    RootFolder := TaskService.GetFolder('\');
    Tasks := RootFolder.GetTasks(1);
    ExecutablePath := ExpandConstant('{app}\{#AppExeName}');
    for I := Tasks.Count downto 1 do
    begin
      Task := Tasks.Item(I);
      TaskName := Task.Name;
      if (TaskName = 'PYAS_Security_ATS') or (Pos('PYAS_Security_ATS_S-1-', TaskName) = 1) then
      begin
        if (Task.Definition.Actions.Count = 1) and
           (CompareText(Task.Definition.Actions.Item(1).Path, ExecutablePath) = 0) then
        begin
          RootFolder.DeleteTask(TaskName, 0);
          Log('Removed PYAS startup task: ' + TaskName);
        end;
      end;
    end;
  except
    Log('Could not remove all PYAS startup tasks');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    RemoveStartupTasks;
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    DelTree(ExpandConstant('{app}'), True, True, True);
  end;
end;
