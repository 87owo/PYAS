pyasrule_dict = {
    "str1": {3: ["physicaldrive0", "%0|%0", "512", "MBR"]},
    "str2": {2: ["bypassuac.dll", "bypassuac.x64.dll", "\\\\.\\pipe\\bypassuac"]},
    "str3": {10:["sysprep.exe", "cliconfg.exe", "eventvwr.exe", "ReflectiveLoader",
                 "[] '%S' exists in DLL hijack location.", "[+] %S ran and exited.",
                 "[] Cleanup failed. Remove: %S", "[+] Privileged file copy success! %S",
                 "[] COM initialization failed.", "[] Privileged file copy failed: %S",
                 "[] Could not write temp DLL to '%S'", "[] Failed to start %S: %d",
                 "[] %S ran too long. Could not terminate the process.", "\\System32",
                 "[*] Wrote hijack DLL to '%S", "[*] Cleanup successful",]},

    "str4": {6: ["ProcessHacker.exe", "MpCmdRun.exe", "ConfigSecurityPolicy.exe", "MSConfig.exe",
                  "Client.exe", "procexp.exe", "MSASCui.exe", "MsMpEng.exe", "MpUXSrv.exe",
                  "NisSrv.exe", "Regedit.exe", "PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY",
                  "dwProcessHandle", "Anti_Process","MutexControl", "CloseMutex"]},

    "ext1": {3: ["shell\\open", "exefile", "batfile", "comfile", "regfile", "mscfile", "cmdfile"]},

    "cmd1": {4: ["taskkill", "-im", "/im", "PYAS.exe", "lsass.exe", "csrss.exe", "smss.exe",
                 "taskmgr.exe", "svchost.exe"]},

    "reg1": {1: ["Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"]}, 
    "reg2": {2: ["NoControlPanel", "NoFileMenu", "NoFind", "NoRealMode", "NoRecentDocsMenu", "NoComponents",
                 "NoSetFolders","NoSetFolderOptions", "NoViewOnDrive", "NoDesktop", "NoAddingComponents", 
                 "NoLogOff", "NoFolderOptions", "DisableCMD", "NoViewContexMenu", "HideClock", "Wallpaper"
                 "NoStartMenuMorePrograms", "NoStartMenuMyGames", "NoStartMenuMyMusic" "NoStartMenuNetworkPlaces",
                 "NoStartMenuPinnedList", "NoActiveDesktop", "NoSetActiveDesktop", "NoActiveDesktopChanges",
                 "NoChangeStartMenu", "ClearRecentDocsOnExit", "NoFavoritesMenu", "DisableLockWorkstation", 
                 "NoSetTaskbar", "NoSMHelp", "NoTrayContextMenu", "NoViewContextMenu", "NoWindowsUpdate",
                 "NoWinKeys", "StartMenuLogOff", "NoSimpleNetlDList", "NoLowDiskSpaceChecks", "Restrict_Run",
                 "NoManageMyComputerVerb", "DisableTaskMgr", "DisableRegistryTools", "DisableChangePassword"]},
}
