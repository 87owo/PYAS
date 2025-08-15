#include <ntifs.h>
#include "ProtectRules.h"
#include "DriverEntry.h"

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
    L"\\DosDevices\\**",
    L"\\Device\\Harddisk*\\Partition\\**",
    L"\\Device\\HarddiskVolume*\\Boot\\**",
    L"\\Device\\HarddiskVolume*\\EFI\\**",
    L"\\Device\\HarddiskVolume*\\bootmgr",
    L"\\Device\\HarddiskVolume*\\Recovery\\**",
    L"\\Device\\HarddiskVolume*\\System Volume Information\\**",
    L"\\Device\\HarddiskVolume*\\Windows\\**",
    L"\\Device\\HarddiskVolume*\\ProgramData\\PYAS\\**",
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

wchar_t* g_BlockReg[] = {
    L"\\REGISTRY\\MACHINE\\BCD00000000\\**",
    L"\\REGISTRY\\MACHINE\\SAM\\**",
    L"\\REGISTRY\\MACHINE\\SECURITY\\**",

    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\**",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\**",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\**",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\MountedDevices\\**",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\Setup\\**",

    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\**",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\MMC\\**",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\**",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\**",
    L"\\REGISTRY\\MACHINE\\**\\Microsoft\\Windows Defender\\**",

    L"\\REGISTRY\\USER\\*_Classes\\CLSID\\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\\**",
    L"\\REGISTRY\\USER\\S-1-*\\SOFTWARE\\NetWire\\**",
    L"\\REGISTRY\\USER\\S-1-*\\SOFTWARE\\Remcos*\\**",
    L"\\REGISTRY\\USER\\S-1-*\\SOFTWARE\\DC3_FEXEC\\**",

    L"\\REGISTRY\\**\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\*\\StubPath",
    L"\\REGISTRY\\**\\SOFTWARE\\Microsoft\\Windows*\\CurrentVersion\\**",
    L"\\REGISTRY\\**\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\\**",

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

static BOOLEAN WildMatchN(const wchar_t* str, SIZE_T n, const wchar_t* pat)
{
    if (*pat == 0)
        return n == 0;
    if (*pat == L'*') {
        if (pat[1] == L'*') {
            for (SIZE_T i = 0; i <= n; ++i) 
                if (WildMatchN(str + i, n - i, pat + 2)) 
                    return TRUE;
            return FALSE;
        }
        SIZE_T i = 0;
        for (; i < n && str[i] != L'\\'; ++i) 
            if (WildMatchN(str + i, n - i, pat + 1))
                return TRUE;
        return WildMatchN(str + i, n - i, pat + 1);
    }
    if (*pat == L'?') 
        return n > 0 && str[0] != L'\\' && WildMatchN(str + 1, n - 1, pat + 1);
    if (n == 0) 
        return FALSE;
    WCHAR sc = str[0], pc = *pat;
    if (sc >= L'A' && sc <= L'Z') 
        sc += 32;
    if (pc >= L'A' && pc <= L'Z') 
        pc += 32;
    return sc == pc && WildMatchN(str + 1, n - 1, pat + 1);
}

static BOOLEAN MatchList(PUNICODE_STRING s, wchar_t** list)
{
    if (!s || !s->Buffer || s->Length == 0)
        return FALSE;
    size_t s_len = s->Length / sizeof(WCHAR);
    for (SIZE_T i = 0; list[i]; ++i) {
        wchar_t* pat = list[i];
        size_t pat_len = wcslen(pat);
        if (wcschr(pat, L'*') || wcschr(pat, L'?')) {
            if (WildMatchN(s->Buffer, s_len, pat)) 
                return TRUE;
        }
        else {
            if (s_len == pat_len && _wcsnicmp(s->Buffer, pat, pat_len) == 0)
                return TRUE;
            if (s_len > pat_len && _wcsnicmp(s->Buffer + s_len - pat_len, pat, pat_len) == 0) 
                return TRUE;
            if (s_len > pat_len && _wcsnicmp(s->Buffer, pat, pat_len) == 0) 
                return TRUE;
        }
    }
    return FALSE;
}

static wchar_t* MatchListGetRule(PUNICODE_STRING s, wchar_t** list)
{
    if (!s || !s->Buffer || s->Length == 0) 
        return 0;
    size_t s_len = s->Length / sizeof(WCHAR);
    for (SIZE_T i = 0; list[i]; ++i) {
        wchar_t* pat = list[i];
        size_t pat_len = wcslen(pat);
        if (wcschr(pat, L'*') || wcschr(pat, L'?')) {
            if (WildMatchN(s->Buffer, s_len, pat)) 
                return pat;
        }
        else {
            if (s_len == pat_len && _wcsnicmp(s->Buffer, pat, pat_len) == 0) 
                return pat;
            if (s_len > pat_len && _wcsnicmp(s->Buffer + s_len - pat_len, pat, pat_len) == 0)
                return pat;
            if (s_len > pat_len && _wcsnicmp(s->Buffer, pat, pat_len) == 0)
                return pat;
        }
    }
    return 0;
}

BOOLEAN IsRegistryBlock(PUNICODE_STRING key, PUNICODE_STRING valueName, PUNICODE_STRING exe)
{
    if (exe && exe->Buffer && exe->Length) {
        if (IsWhitelist(exe))
            return FALSE;
    }
    if (key && key->Buffer && key->Length) {
        if (MatchBlockReg(key))
            return TRUE;
    }
    if (valueName && valueName->Buffer && valueName->Length) {
        SIZE_T n = valueName->Length / sizeof(WCHAR);
        for (SIZE_T i = 0; g_BlockReg[i]; ++i) {
            wchar_t* pat = g_BlockReg[i];
            if (wcschr(pat, L'\\') || wcschr(pat, L'*') || wcschr(pat, L'?'))
                continue;
            size_t m = wcslen(pat);
            if (n == m && _wcsnicmp(valueName->Buffer, pat, m) == 0)
                return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN GetProcessImagePathByPid(HANDLE pid, PUNICODE_STRING ProcessImagePath)
{
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status))
        return FALSE;

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
    UNICODE_STRING* image = NULL;
    status = SeLocateProcessImageName(process, &image);
   
    if (NT_SUCCESS(status) && image) {
        if (ProcessImagePath->MaximumLength >= image->Length + sizeof(WCHAR)) {
            RtlCopyMemory(ProcessImagePath->Buffer, image->Buffer, image->Length);
            ProcessImagePath->Length = image->Length;
            ProcessImagePath->Buffer[image->Length / sizeof(WCHAR)] = 0;
            ExFreePool(image);
            ObDereferenceObject(process);
            return TRUE;
        }
        ExFreePool(image);
    }
#endif
    {
        PCSTR nameA = PsGetProcessImageFileName(process);
        if (nameA) {
            ANSI_STRING as;
            UNICODE_STRING us = { 0 };
            RtlInitAnsiString(&as, nameA);
            
            if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&us, &as, TRUE)) && ProcessImagePath->MaximumLength >= us.Length + sizeof(WCHAR)) {
                RtlCopyMemory(ProcessImagePath->Buffer, us.Buffer, us.Length);
                ProcessImagePath->Length = us.Length;
                ProcessImagePath->Buffer[us.Length / sizeof(WCHAR)] = 0;
                RtlFreeUnicodeString(&us);
                ObDereferenceObject(process);
                return TRUE;
            }
            RtlFreeUnicodeString(&us);
        }
    }
    ObDereferenceObject(process);
    return FALSE;
}

BOOLEAN IsWhitelist(PUNICODE_STRING s)
{
    if (MatchList(s, g_WhitelistExcept)) 
        return FALSE;
    return MatchList(s, g_Whitelist);
}

BOOLEAN MatchBlockReg(PUNICODE_STRING s)
{
    return MatchList(s, g_BlockReg);
}

wchar_t* GetMatchedBlockRegRule(PUNICODE_STRING s)
{
    return MatchListGetRule(s, g_BlockReg);
}
