#include <ntifs.h>
#include "ProtectRules.h"

wchar_t* g_Whitelist[] = {
    L"\\Device\\HarddiskVolume*\\Windows\\**",
    L"\\Device\\HarddiskVolume*\\Program*\\**",
    L"\\Device\\HarddiskVolume*\\Users\\*\\AppData\\**",
    L"**\\PYAS*.exe",
    L"Registry",
    L"vmmem*",
    NULL
};

wchar_t* g_WhitelistExcept[] = {
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\vds.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\bcdedit.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\reg.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\cmd.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\mshta.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\wscript.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\cscript.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\schtasks.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\diskpart.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\format.com",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\mountvol.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\wbadmin.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\bcdboot.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\dism.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\bootsect.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\cipher.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\net.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\net1.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\msiexec.exe",
    L"\\Device\\HarddiskVolume*\\Windows\\Sys*\\WindowsPowerShell\\*\\powershell.exe",
    L"\\Device\\HarddiskVolume*\\Program*\\PowerShell\\*\\pwsh.exe",
    NULL
};

wchar_t* g_AttachDisk[] = {
    L"\\FileSystem\\Ntfs",
    L"\\FileSystem\\Refs",
    L"\\FileSystem\\Fastfat",
    L"\\FileSystem\\exfat",
    L"\\FileSystem\\Udfs",
    NULL
};

wchar_t* g_BlockFile[] = {
    L"\\Device\\Harddisk*\\DR*",
    L"\\Device\\Harddisk*\\Partition\\**",
    L"\\Device\\HarddiskVolume*\\Boot\\**",
    L"\\Device\\HarddiskVolume*\\EFI\\**",
    L"\\Device\\HarddiskVolume*\\bootmgr",
    L"\\Device\\HarddiskVolume*\\Recovery\\**",
    L"\\Device\\HarddiskVolume*\\System Volume Information\\**",
    L"\\Device\\HarddiskVolume*\\Windows\\**",
    L"\\Device\\HarddiskVolume*\\$*\\**",
    L"\\Device\\HarddiskVolume*\\ProgramData\\PYAS\\**",
    L"**\\PYAS.exe",
    
    L"**\\CON**",
    L"**\\PRN**",
    L"**\\AUX**",
    L"**\\NUL**",
    L"**\\COM*\\**",
    L"**\\LPT*\\**",
    L"**\\evil*.exe",
    L"**\\OSDATA**",
    NULL
};

wchar_t* g_BlockRansom[] = {
    L"\\Device\\HarddiskVolume*\\Users\\*\\Desktop\\**",
    L"\\Device\\HarddiskVolume*\\Users\\*\\Downloads\\**",
    L"\\Device\\HarddiskVolume*\\Users\\*\\Documents\\**",
    L"\\Device\\HarddiskVolume*\\Users\\*\\Music\\**",
    L"\\Device\\HarddiskVolume*\\Users\\*\\Pictures\\**",
    L"\\Device\\HarddiskVolume*\\Users\\*\\Videos\\**",
    NULL
};

wchar_t* g_Blocksuffix[] = {
    L".exe", L".dll", L".sys", L".com", L".scr",
    L".zip", L".7z", L".rar", L".tar", L".gz",
    L".js", L".bat", L".cmd", L".ps1", L".vbs",
    L".ppt", L".pptx", L".wps", L".txt", L".rtf",
    L".pdf", L".xls", L".xlsx", L".doc", L".docx",
    L".jpg", L".jpeg", L".png", L".webp", L".gif",
    L".mp3", L".wav", L".aac", L".ogg", L".flac",
    L".mp4", L".avi", L".mov", L".wmv", L".mkv",
    L".aux", L".cur", L".mui", L".ttf", L".efi",
    NULL
};

wchar_t* g_BlockReg[] = {
    L"\\REGISTRY\\MACHINE\\BCD00000000\\**",
    L"\\REGISTRY\\MACHINE\\SAM\\**",
    L"\\REGISTRY\\MACHINE\\SECURITY\\**",

    L"\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\**",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Enum\\**",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\**",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\MountedDevices\\**",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\Setup\\**",

    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\**",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\MMC\\**",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\**",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\**",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid",
    L"\\REGISTRY\\MACHINE\\**\\Microsoft\\Windows Defender\\**",

    L"\\REGISTRY\\**\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\*\\StubPath",
    L"\\REGISTRY\\**\\SOFTWARE\\Microsoft\\Windows*\\CurrentVersion\\**",
    L"\\REGISTRY\\**\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\\**",

    L"\\REGISTRY\\USER\\*_Classes\\*\\shell\\open\\command\\**",
    L"\\REGISTRY\\USER\\*_Classes\\CLSID\\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\\**",
    L"\\REGISTRY\\USER\\S-1-*\\SOFTWARE\\NetWire\\**",
    L"\\REGISTRY\\USER\\S-1-*\\SOFTWARE\\Remcos*\\**",
    L"\\REGISTRY\\USER\\S-1-*\\SOFTWARE\\DC3_FEXEC\\**",

    L"DisableAntiSpyware",
    L"DisableWindowsUpdateAccess",
    L"EnableLUA",
    L"ConsentPromptBehaviorAdmin",
    L"NoControlPanel",
    L"NoDrives",
    L"NoFileMenu",
    L"NoFind",
    L"NoStartMenuPinnedList",
    L"NoSetFolders",
    L"NoSetFolderOptions",
    L"NoViewOnDrive",
    L"NoClose",
    L"NoDesktop",
    L"NoLogoff",
    L"NoFolderOptions",
    L"RestrictRun",
    L"NoViewContextMenu",
    L"HideClock",
    L"NoStartMenuMyGames",
    L"NoStartMenuMyMusic",
    L"DisableCMD",
    L"NoAddingComponents",
    L"NoWinKeys",
    L"NoStartMenuLogOff",
    L"NoSimpleNetIDList",
    L"NoLowDiskSpaceChecks",
    L"DisableLockWorkstation",
    L"Restrict_Run",
    L"DisableTaskMgr",
    L"DisableRegistryTools",
    L"DisableChangePassword",
    L"Wallpaper",
    L"NoComponents",
    L"NoStartMenuMorePrograms",
    L"NoActiveDesktop",
    L"NoSetActiveDesktop",
    L"NoRecentDocsMenu",
    L"NoWindowsUpdate",
    L"NoChangeStartMenu",
    L"NoFavoritesMenu",
    L"NoRecentDocsHistory",
    L"NoSetTaskbar",
    L"NoSMHelp",
    L"NoTrayContextMenu",
    L"NoManageMyComputerVerb",
    L"NoRealMode",
    L"NoRun",
    L"ClearRecentDocsOnExit",
    L"NoActiveDesktopChanges",
    L"NoStartMenuNetworkPlaces",
    L"NoLockScreen",
    L"HideFastUserSwitching",
    L"ConsentPromptBehaviorUser",
    L"EnableSecureUIAPaths",
    L"NoSRM",
    L"NoInteractiveServices",
    L"ShutdownWithoutLogon",
    L"AutoAdminLogon",
    L"ImagePath",
    L"BootExecute",
    L"SubSystems",
    L"FirmwareBootDevice",
    L"BootDriverFlags",
    L"SystemStartOptions",
    L"CrashDumpEnabled",
    L"DisableAutomaticRestartOnFailure",
    L"SystemBiosVersion",
    L"NoTheme",
    L"PendingFileRenameOperations",
    L"SystemSetupInProgress",
    L"CmdLine",
    L"SetupType",
    L"AutoReboot",
    L"Shell",
    L"Userinit",
    L"UIHost",
    L"Debugger",
    L"DefaultUserName",
    L"DefaultPassword",
    L"AltDefaultUserName",
    L"AltDefaultPassword",
    L"DisableCAD",
    L"LegalNoticeCaption",
    L"LegalNoticeText",
    NULL
};

wchar_t* g_RemoteSuspectBins[] = {
    L"powershell.exe",
    L"pwsh.exe",
    L"wscript.exe",
    L"cscript.exe",
    L"mshta.exe",
    L"rundll32.exe",
    L"regsvr32.exe",
    L"cmd.exe",
    L"bitsadmin.exe",
    L"msbuild.exe",
    L"installutil.exe",
    L"wmic.exe",
    NULL
};

wchar_t* g_RemoteCmdIndicatorsHttp[] = {
    L"http://",
    L"https://",
    NULL
};

wchar_t* g_RemoteCmdIndicatorsGeneric[] = {
    L"-enc",
    L" -e ",
    L"-encodedcommand",
    L"frombase64string(",
    L"iex(",
    L"downloadstring(",
    NULL
};

wchar_t* g_RemoteCmdFromCmdExe[] = {
    L"powershell",
    L"pwsh",
    L"mshta",
    L"rundll32",
    L"wscript",
    L"cscript",
    NULL
};

wchar_t* g_RemoteCmdFromRundll32Exe[] = {
    L".dll,",
    L"javascript:",
    L"http",
    NULL
};

wchar_t* g_RemoteCmdRegsvr32Need[] = {
    L"/i:",
    NULL
};

wchar_t* g_RemoteCmdFromMshtaExe[] = {
    L"http://",
    L"https://",
    NULL
};

wchar_t* g_ScreenCapModules[] = {
    L"windows.graphics.capture.dll",
    L"dxgi.dll",
    L"d3d11.dll",
    L"dwmapi.dll",
    L"dcomp.dll",
    L"mfreadwrite.dll",
    L"mfplat.dll",
    L"opengl32.dll",
    L"gdi32full.dll",
    L"win32u.dll",
    NULL
};

wchar_t* g_ScreenUserSubdirs[] = {
    L"\\AppData\\",
    L"\\Temp\\",
    L"\\Downloads\\",
    NULL
};

wchar_t* g_ScreenOtherProcNeedles[] = {
    L"\\ProgramData\\",
    NULL
};
