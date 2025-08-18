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
    L"\\Device\\HarddiskVolume*\\$*\\**",
    
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

static __forceinline BOOLEAN USOK(PUNICODE_STRING s)
{
    return s && s->Buffer && s->Length;
}

BOOLEAN IsRegistryBlock(PUNICODE_STRING key, PUNICODE_STRING valueName, PUNICODE_STRING exe)
{
    if (USOK(exe)) {
        if (IsWhitelist(exe))
            return FALSE;
    }
    if (USOK(exe) && USOK(key)) {
        size_t elen = exe->Length / sizeof(WCHAR);
        size_t klen = key->Length / sizeof(WCHAR);
        if (((elen >= 12 && _wcsnicmp(exe->Buffer + elen - 12, L"services.exe", 12) == 0) ||
            (elen >= 11 && _wcsnicmp(exe->Buffer + elen - 11, L"svchost.exe", 11) == 0) ||
            (elen >= 6 && _wcsnicmp(exe->Buffer + elen - 6, L"sc.exe", 6) == 0))) {
            if (WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\SYSTEM\\CurrentControlSet\\Services\\**"))
                return FALSE;
        }
        if ((elen >= 14 && _wcsnicmp(exe->Buffer + elen - 14, L"powershell.exe", 14) == 0) ||
            (elen >= 8 && _wcsnicmp(exe->Buffer + elen - 8, L"pwsh.exe", 8) == 0)) {
            if (WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\CurrentVersion\\Internet Settings\\ZoneMap") ||
                WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\CurrentVersion\\Internet Settings\\ZoneMap\\**") ||
                WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\CurrentVersion\\Notifications\\Data") ||
                WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\CurrentVersion\\Notifications\\Data\\**"))
                return FALSE;
        }
        if ((elen >= 11 && _wcsnicmp(exe->Buffer + elen - 11, L"msiexec.exe", 11) == 0) || 
            (elen >= 20 && _wcsnicmp(exe->Buffer + elen - 20, L"TrustedInstaller.exe", 20) == 0)) {
            if (WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\CurrentVersion\\Installer\\**") ||
                WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\CurrentVersion\\Uninstall\\**") ||
                WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\SYSTEM\\CurrentControlSet\\Services\\**"))
                return FALSE;
        }
        if (elen >= 12 && _wcsnicmp(exe->Buffer + elen - 12, L"schtasks.exe", 12) == 0) {
            if (WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\**"))
                return FALSE;
        }
    }
    if (USOK(key)) {
        if (MatchBlockReg(key))
            return TRUE;
    }
    if (USOK(valueName)) {
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

    HANDLE h = NULL;
    status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL, PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, KernelMode, &h);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return FALSE;
    }
    ULONG len = 0;
    status = ZwQueryInformationProcess(h, ProcessImageFileName, NULL, 0, &len);
    if (status != STATUS_INFO_LENGTH_MISMATCH || len == 0) {
        ZwClose(h);
        ObDereferenceObject(process);
        return FALSE;
    }
    PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, len, 'iPgN');
    if (!buf) {
        ZwClose(h);
        ObDereferenceObject(process);
        return FALSE;
    }
    status = ZwQueryInformationProcess(h, ProcessImageFileName, buf, len, &len);
    if (NT_SUCCESS(status)) {
        PUNICODE_STRING image = (PUNICODE_STRING)buf;
        if (image->Buffer && image->Length > 0 && ProcessImagePath->MaximumLength >= image->Length + sizeof(WCHAR)) {
            RtlCopyMemory(ProcessImagePath->Buffer, image->Buffer, image->Length);
            ProcessImagePath->Length = image->Length;
            ProcessImagePath->Buffer[image->Length / sizeof(WCHAR)] = 0;
            ExFreePool2(buf, 'iPgN', NULL, 0);
            ZwClose(h);
            ObDereferenceObject(process);
            return TRUE;
        }
    }
    ExFreePool2(buf, 'iPgN', NULL, 0);
    ZwClose(h);
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
