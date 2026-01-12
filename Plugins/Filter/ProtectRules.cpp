#include "DriverCommon.h"

constexpr auto MAX_TRACKERS = 64;
constexpr auto RANSOM_TIME_WINDOW_MS = 3000;
constexpr auto RANSOM_COUNT_THRESHOLD = 5;
constexpr auto HIGH_ENTROPY_THRESHOLD = 15;

typedef struct _RANSOM_TRACKER {
    HANDLE ProcessId;
    ULONG ActivityCount;
    LARGE_INTEGER LastActivityTime;
} RANSOM_TRACKER, * PRANSOM_TRACKER;

RANSOM_TRACKER RansomTrackers[MAX_TRACKERS];

const PCWSTR SafeSystemBinaries[] = {
    L"*\\Windows\\System32\\lsass.exe",
    L"*\\Windows\\System32\\services.exe",
    L"*\\Windows\\System32\\csrss.exe",
    L"*\\Windows\\System32\\smss.exe",
    L"*\\Windows\\System32\\wininit.exe",
    L"*\\Windows\\System32\\winlogon.exe",
    L"*\\Windows\\System32\\svchost.exe",
    L"*\\Windows\\System32\\SearchIndexer.exe",
    L"*\\Windows\\System32\\msiexec.exe",
    L"*\\Windows\\System32\\TrustedInstaller.exe",
    L"*\\Windows\\System32\\TiWorker.exe",
    L"*\\Windows\\System32\\dism.exe",
    L"*\\Windows\\System32\\dismhost.exe",
    L"*\\Windows\\System32\\wuauclt.exe",
    L"*\\Windows\\System32\\taskhostw.exe",
    L"*\\Windows\\System32\\MoUsoCoreWorker.exe",
    L"*\\Windows\\System32\\sppsvc.exe",
    L"*\\Windows\\System32\\backgroundTaskHost.exe",
    L"*\\Windows\\System32\\RuntimeBroker.exe",
    L"*\\Windows\\System32\\ctfmon.exe",
    L"*\\Windows\\System32\\smartscreen.exe",
    L"*\\Windows\\System32\\Taskmgr.exe",
    L"*\\Windows\\ImmersiveControlPanel\\SystemSettings.exe"
};

const PCWSTR CriticalSystemBinaries[] = {
    L"*\\Windows\\ImmersiveControlPanel\\SystemSettings.exe",
    L"*\\Windows Defender\\MsMpEng.exe",
    L"*\\Windows\\System32\\lsass.exe",
    L"*\\Windows\\System32\\services.exe",
    L"*\\Windows\\System32\\wininit.exe",
    L"*\\Windows\\System32\\winlogon.exe",
    L"*\\Windows\\System32\\svchost.exe",
    L"*\\Windows\\System32\\smss.exe",
    L"*\\Windows\\System32\\csrss.exe",
    L"*\\Windows\\System32\\sppsvc.exe",
    L"*\\Windows\\System32\\msiexec.exe",
    L"*\\Windows\\System32\\TrustedInstaller.exe",
    L"*\\Windows\\System32\\TiWorker.exe",
    L"*\\Windows\\System32\\dism.exe",
    L"*\\Windows\\System32\\dismhost.exe",
    L"*\\Windows\\System32\\SgrmBroker.exe",
    L"*\\Windows\\System32\\WerFault.exe",
    L"*\\Windows\\System32\\wbem\\WmiApSrv.exe",
    L"*\\Windows\\System32\\wbem\\WmiPrvSE.exe",
    L"*\\Windows\\ImmersiveControlPanel\\SystemSettings.exe",
    L"*\\Windows\\System32\\ctfmon.exe",
    L"*\\Windows\\System32\\taskhostw.exe",
    L"*\\Windows\\System32\\fontdrvhost.exe",
    L"*\\Windows\\System32\\dwm.exe",
    L"*\\Windows\\System32\\SearchIndexer.exe",
    L"*\\Windows\\System32\\SearchProtocolHost.exe",
    L"*\\Windows\\System32\\SearchFilterHost.exe",
    L"*\\Windows\\System32\\smartscreen.exe",
    L"*\\Windows\\System32\\vssvc.exe",
    L"*\\Windows\\System32\\cleanmgr.exe",
    L"*\\Windows\\System32\\defrag.exe",
    L"*\\Windows\\System32\\chkdsk.exe",
    L"*\\Windows\\System32\\conhost.exe",
    L"*\\Windows\\System32\\RecoveryDrive.exe"
};

const PCWSTR SafeProcessPatterns[] = {
    L"*\\Windows Defender\\*",
    L"*\\Windows Defender Advanced Threat Protection\\*",

    L"*\\Program*\\*",
    L"*\\AppData\\Local\\*",
    L"*\\AppData\\Roaming\\*",

    L"*\\Google\\Update\\*",
    L"*\\Google\\Chrome\\Application\\chrome.exe",
    L"*\\Internet Explorer\\iexplore.exe",
    L"*\\Microsoft\\EdgeUpdate\\*",
    L"*\\Microsoft\\Edge\\Application\\msedge.exe",
    L"*\\Microsoft\\EdgeWebView\\Application\\*",
    L"*\\Mozilla Firefox\\firefox.exe",
    L"*\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
    L"*\\Opera Software\\*\\opera.exe",
    L"*\\Vivaldi\\Application\\vivaldi.exe",

    L"*\\WinRAR\\WinRAR.exe",
    L"*\\WinRAR\\UnRAR.exe",
    L"*\\7-Zip\\7zG.exe",
    L"*\\7-Zip\\7zFM.exe",
    L"*\\Bandizip\\Bandizip.exe",

    L"*\\Microsoft Office\\root\\Office*\\*.EXE",
    L"*\\Microsoft Office\\root\\Office*\\WINWORD.EXE",
    L"*\\Microsoft Office\\root\\Office*\\EXCEL.EXE",
    L"*\\Microsoft Office\\root\\Office*\\POWERPNT.EXE",
    L"*\\Adobe\\Acrobat*\\*\\Acrobat.exe",
    L"*\\Adobe\\Acrobat*\\*\\AcroRd32.exe",
    L"*\\Foxit PDF Reader\\FoxitPDFReader.exe",
    L"*\\LibreOffice*\\program\\soffice.bin",
    L"*\\LibreOffice*\\program\\soffice.exe",
    L"*\\Notepad++\\notepad++.exe",
    L"*\\Sublime Text*\\sublime_text.exe",

    L"*\\Microsoft\\Teams\\*\\Teams.exe",
    L"*\\Zoom\\bin\\Zoom.exe",
    L"*\\Slack\\app-*\\slack.exe",
    L"*\\Telegram Desktop\\Telegram.exe",
    L"*\\WhatsApp\\WhatsApp.exe",
    L"*\\Discord\\app-*\\Discord.exe",

    L"*\\Microsoft Visual Studio\\*\\devenv.exe",
    L"*\\Microsoft VS Code\\Code.exe",
    L"*\\Git\\cmd\\git.exe",
    L"*\\Git\\mingw64\\bin\\git.exe",
    L"*\\bin\\cmake.exe",
    L"*\\nodejs\\node.exe",
    L"*\\Android Studio\\bin\\studio64.exe",
    L"*\\JetBrains\\*\\bin\\*.exe",

    L"*\\Dropbox\\Client\\Dropbox.exe",
    L"*\\Google\\Drive\\*\\GoogleDriveFS.exe",
    L"*\\Microsoft OneDrive\\OneDrive.exe",

    L"*\\Sangfor\\*",
    L"*\\SogouInput\\*",
    L"*\\baidu\\BaiduNetdisk\\*",
    L"*\\TortoiseSVN\\*",
    L"*\\TortoiseGit\\*",
    L"*\\TortoiseOverlays\\*",

    L"*\\VideoLAN\\VLC\\vlc.exe",
    L"*\\Spotify\\Spotify.exe",
    L"*\\obs-studio\\bin\\*\\obs64.exe",
    L"*\\DaVinci Resolve\\Resolve.exe",
    L"*\\Adobe\\Adobe Premiere Pro*\\Adobe Premiere Pro.exe",
    L"*\\Adobe\\Adobe Photoshop*\\Photoshop.exe",

    L"*\\Steam\\steam.exe",
    L"*\\Steam\\bin\\steamwebhelper.exe",
    L"*\\Steam\\steamapps\\*",
    L"*\\Epic Games\\Launcher\\Portal\\Binaries\\*\\EpicGamesLauncher.exe",
    L"*\\Battle.net\\*\\Battle.net.exe",

    L"*\\NVIDIA Corporation\\*",
    L"*\\AMD\\*",
    L"*\\Intel\\*",
    L"*\\Logitech\\*",
    L"*\\Razer\\*",
    L"*\\Corsair\\*",
    L"*\\ASUS\\*"
};

const PCWSTR RegistryBlockList[] = {
    L"\\REGISTRY\\MACHINE\\BCD00000000",
    L"\\REGISTRY\\MACHINE\\BCD00000000\\*",
    L"\\REGISTRY\\MACHINE\\SAM",
    L"\\REGISTRY\\MACHINE\\SAM\\*",
    L"\\REGISTRY\\MACHINE\\SECURITY",
    L"\\REGISTRY\\MACHINE\\SECURITY\\*",
    L"\\REGISTRY\\MACHINE\\SYSTEM",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\*",

    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\*",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\*",

    L"\\REGISTRY\\USER\\*_Classes\\*\\shell\\open\\command\\*",
    L"\\REGISTRY\\USER\\S-1-*\\SOFTWARE\\NetWire\\*",
    L"\\REGISTRY\\USER\\S-1-*\\SOFTWARE\\Remcos*\\*",
    L"\\REGISTRY\\USER\\S-1-*\\SOFTWARE\\DC3_FEXEC\\*",
    L"*\\Image File Execution Options\\*",

    L"*\\Classes\\.exe",
    L"*\\Classes\\.bat",
    L"*\\Classes\\.cmd",
    L"*\\Classes\\.com",
    L"*\\Classes\\exefile\\*",
    L"*\\Classes\\batfile\\*",
    L"*\\Classes\\cmdfile\\*",
    L"*\\Classes\\comfile\\*",
    L"*\\DefaultIcon",

    L"*\\DisableAntiSpyware",
    L"*\\DisableWindowsUpdateAccess",
    L"*\\EnableLUA",
    L"*\\ConsentPromptBehaviorAdmin",
    L"*\\NoControlPanel",
    L"*\\NoDrives",
    L"*\\NoFileMenu",
    L"*\\NoFind",
    L"*\\NoStartMenuPinnedList",
    L"*\\NoSetFolders",
    L"*\\NoSetFolderOptions",
    L"*\\NoViewOnDrive",
    L"*\\NoClose",
    L"*\\NoDesktop",
    L"*\\NoLogoff",
    L"*\\NoFolderOptions",
    L"*\\RestrictRun",
    L"*\\NoViewContextMenu",
    L"*\\HideClock",
    L"*\\NoStartMenuMyGames",
    L"*\\NoStartMenuMyMusic",
    L"*\\DisableCMD",
    L"*\\NoAddingComponents",
    L"*\\NoWinKeys",
    L"*\\NoStartMenuLogOff",
    L"*\\NoSimpleNetIDList",
    L"*\\NoLowDiskSpaceChecks",
    L"*\\DisableLockWorkstation",
    L"*\\Restrict_Run",
    L"*\\DisableTaskMgr",
    L"*\\DisableRegistryTools",
    L"*\\DisableChangePassword",
    L"*\\Wallpaper",
    L"*\\NoComponents",
    L"*\\NoStartMenuMorePrograms",
    L"*\\NoActiveDesktop",
    L"*\\NoSetActiveDesktop",
    L"*\\NoRecentDocsMenu",
    L"*\\NoWindowsUpdate",
    L"*\\NoChangeStartMenu",
    L"*\\NoFavoritesMenu",
    L"*\\NoRecentDocsHistory",
    L"*\\NoSetTaskbar",
    L"*\\NoSMHelp",
    L"*\\NoTrayContextMenu",
    L"*\\NoManageMyComputerVerb",
    L"*\\NoRealMode",
    L"*\\NoRun",
    L"*\\ClearRecentDocsOnExit",
    L"*\\NoActiveDesktopChanges",
    L"*\\NoStartMenuNetworkPlaces",
    L"*\\NoLockScreen",
    L"*\\HideFastUserSwitching",
    L"*\\ConsentPromptBehaviorUser",
    L"*\\EnableSecureUIAPaths",
    L"*\\NoSRM",
    L"*\\NoInteractiveServices",
    L"*\\ShutdownWithoutLogon",
    L"*\\AutoAdminLogon",
    L"*\\ImagePath",
    L"*\\BootExecute",
    L"*\\SubSystems",
    L"*\\FirmwareBootDevice",
    L"*\\BootDriverFlags",
    L"*\\SystemStartOptions",
    L"*\\CrashDumpEnabled",
    L"*\\DisableAutomaticRestartOnFailure",
    L"*\\SystemBiosVersion",
    L"*\\NoTheme",
    L"*\\PendingFileRenameOperations",
    L"*\\SystemSetupInProgress",
    L"*\\CmdLine",
    L"*\\SetupType",
    L"*\\AutoReboot",
    L"*\\Userinit",
    L"*\\UIHost",
    L"*\\Debugger",
    L"*\\DefaultUserName",
    L"*\\DefaultPassword",
    L"*\\AltDefaultUserName",
    L"*\\AltDefaultPassword",
    L"*\\DisableCAD",
    L"*\\LegalNoticeCaption",
    L"*\\LegalNoticeText",
    L"*\\Run",
    L"*\\RunOnce",
};

const PCWSTR DangerousExtensions[] = {
    L".exe", L".dll", L".sys", L".com", L".scr",
    L".zip", L".7z", L".rar", L".tar", L".gz",
    L".js", L".bat", L".cmd", L".ps1", L".vbs",
    L".ppt", L".pptx", L".wps", L".txt", L".rtf",
    L".pdf", L".xls", L".xlsx", L".doc", L".docx",
    L".jpg", L".jpeg", L".png", L".webp", L".gif",
    L".mp3", L".wav", L".aac", L".ogg", L".flac",
    L".mp4", L".avi", L".mov", L".wmv", L".mkv",
    L".aux", L".cur", L".mui", L".ttf", L".efi"
};

const PCWSTR NaturallyCompressedExtensions[] = {
    L".zip", L".7z", L".rar", L".tar", L".gz",
    L".jpg", L".jpeg", L".png", L".webp", L".gif",
    L".mp3", L".wav", L".aac", L".ogg", L".flac",
    L".mp4", L".avi", L".mov", L".wmv", L".mkv",
    L".exe", L".dll", L".sys", L".mui", L".scr",
    L".docx", L".xlsx", L".pptx", L".pdf", L".wps",
    L".apk", L".jar", L".class", L".db", L".sqlite"
};

const PCWSTR ProtectedPaths[] = {
    L"*\\PYAS.exe",
    L"*\\PYAS_Driver.sys",
    L"*\\ProgramData\\PYAS\\*.json",

    L"*\\Windows\\System32\\config\\SAM*",
    L"*\\Windows\\System32\\config\\SECURITY*",
    L"*\\Windows\\System32\\config\\SOFTWARE*",
    L"*\\Windows\\System32\\config\\SYSTEM*",
    L"*\\Windows\\System32\\config\\DEFAULT*",
    L"*\\Windows\\System32\\config\\RegBack\\*",

    L"*\\Windows\\System32\\drivers\\*",
    L"*\\Windows\\System32\\drivers\\etc\\hosts",
    L"*\\Windows\\System32\\*.exe",
    L"*\\Windows\\System32\\*.dll",
    L"*\\Windows\\SysWOW64\\*.exe",
    L"*\\Windows\\SysWOW64\\*.dll",
    L"*\\Windows\\Web\\Wallpaper\\*",
    L"*\\Windows\\explorer.exe",
    L"*\\Windows\\regedit.exe",

    L"*\\bootmgr",
    L"*\\boot.ini",
    L"*\\BOOTNXT",
    L"*\\EFI",
    L"*\\EFI\\*",
    L"*\\Boot",
    L"*\\Boot\\*",
    L"*\\Recovery",
    L"*\\Recovery\\*",
    L"*\\System Volume Information\\*",

    L"*\\CON",
    L"*\\CON\\*",
    L"*\\PRN",
    L"*\\PRN\\*",
    L"*\\AUX",
    L"*\\AUX\\*",
    L"*\\NUL",
    L"*\\NUL\\*",
    L"*\\CLOCK$",
    L"*\\CLOCK$\\*",
    L"*\\COM?",
    L"*\\COM?\\*",
    L"*\\LPT?",
    L"*\\LPT?\\*",
    L"*\\COM0",
    L"*\\COM0\\*",
    L"*\\LPT0",
    L"*\\LPT0\\*",
    L"*\\$Mft",
    L"*\\$Mft\\*",
    L"*\\$MftMirr",
    L"*\\$MftMirr\\*",
    L"*\\$LogFile",
    L"*\\$LogFile\\*",
    L"*\\$Volume",
    L"*\\$Volume\\*",
    L"*\\$AttrDef",
    L"*\\$AttrDef\\*",
    L"*\\$Bitmap",
    L"*\\$Bitmap\\*",
    L"*\\$Boot",
    L"*\\$Boot\\*",
    L"*\\$BadClus",
    L"*\\$BadClus\\*",
    L"*\\$Secure",
    L"*\\$Secure\\*",
    L"*\\$Upcase",
    L"*\\$Upcase\\*",
    L"*\\OSDATA",
    L"*\\OSDATA\\*",

    L"*:*",
    L"*<*",
    L"*>*",
    L"*|*",
};

static BOOLEAN HasSuffix(PCUNICODE_STRING String, PCWSTR Suffix) {
    if (!String || !String->Buffer || !Suffix) return FALSE;

    SIZE_T StringLenChars = String->Length / sizeof(WCHAR);
    SIZE_T SuffixLenChars = 0;

    while (Suffix[SuffixLenChars] != L'\0') {
        SuffixLenChars++;
    }

    if (StringLenChars < SuffixLenChars) return FALSE;

    PCWSTR Ptr = String->Buffer + (StringLenChars - SuffixLenChars);

    for (SIZE_T i = 0; i < SuffixLenChars; i++) {
        if (RtlDowncaseUnicodeChar(Ptr[i]) != RtlDowncaseUnicodeChar(Suffix[i])) {
            return FALSE;
        }
    }
    return TRUE;
}

BOOLEAN WildcardMatch(PCWSTR Pattern, PCWSTR String, USHORT StringLengthBytes) {
    if (!Pattern || !String) return FALSE;

    PCWSTR mp = NULL;
    PCWSTR cp = NULL;
    PCWSTR StringEnd = (PCWSTR)((PUCHAR)String + StringLengthBytes);

    while (String < StringEnd) {
        if (*Pattern == L'*') {
            mp = ++Pattern;
            cp = String + 1;
        }
        else if (*Pattern == L'?' || (RtlDowncaseUnicodeChar(*Pattern) == RtlDowncaseUnicodeChar(*String))) {
            Pattern++;
            String++;
        }
        else if (mp) {
            Pattern = mp;
            String = cp++;
        }
        else {
            return FALSE;
        }
    }
    while (*Pattern == L'*') {
        Pattern++;
    }
    return !*Pattern;
}

static NTSTATUS GetProcessImageName(HANDLE ProcessId, PUNICODE_STRING* ImageName) {
    NTSTATUS status;
    PEPROCESS Process = NULL;

    *ImageName = NULL;
    status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(status)) return status;

    status = SeLocateProcessImageName(Process, ImageName);
    ObDereferenceObject(Process);

    return status;
}

BOOLEAN IsProcessTrusted(HANDLE ProcessId) {
    if ((ULONG)(ULONG_PTR)ProcessId == GlobalData.PyasPid) return TRUE;
    if (ProcessId == (HANDLE)4) return TRUE;
    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;

    PUNICODE_STRING imageFileName = NULL;
    NTSTATUS status = GetProcessImageName(ProcessId, &imageFileName);
    BOOLEAN isTrusted = FALSE;

    if (NT_SUCCESS(status) && imageFileName && imageFileName->Buffer) {
        for (SIZE_T i = 0; i < sizeof(SafeSystemBinaries) / sizeof(SafeSystemBinaries[0]); i++) {
            if (WildcardMatch(SafeSystemBinaries[i], imageFileName->Buffer, imageFileName->Length)) {
                isTrusted = TRUE;
                goto cleanup;
            }
        }
        for (SIZE_T i = 0; i < sizeof(SafeProcessPatterns) / sizeof(SafeProcessPatterns[0]); i++) {
            if (WildcardMatch(SafeProcessPatterns[i], imageFileName->Buffer, imageFileName->Length)) {
                isTrusted = TRUE;
                goto cleanup;
            }
        }
    }

cleanup:
    if (imageFileName) ExFreePool(imageFileName);
    return isTrusted;
}

BOOLEAN IsCriticalSystemProcess(HANDLE ProcessId) {
    if ((ULONG)(ULONG_PTR)ProcessId == GlobalData.PyasPid) return TRUE;
    if (ProcessId == (HANDLE)4) return TRUE;
    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;

    PUNICODE_STRING imageFileName = NULL;
    NTSTATUS status = GetProcessImageName(ProcessId, &imageFileName);
    BOOLEAN isCritical = FALSE;

    if (NT_SUCCESS(status) && imageFileName && imageFileName->Buffer) {
        for (SIZE_T i = 0; i < sizeof(CriticalSystemBinaries) / sizeof(CriticalSystemBinaries[0]); i++) {
            if (WildcardMatch(CriticalSystemBinaries[i], imageFileName->Buffer, imageFileName->Length)) {
                isCritical = TRUE;
                goto cleanup;
            }
        }
    }

cleanup:
    if (imageFileName) ExFreePool(imageFileName);
    return isCritical;
}

BOOLEAN IsInstallerProcess(HANDLE ProcessId) {
    return IsProcessTrusted(ProcessId);
}

BOOLEAN IsTargetProtected(HANDLE ProcessId) {
    if ((ULONG)(ULONG_PTR)ProcessId == GlobalData.PyasPid) return TRUE;
    return FALSE;
}

BOOLEAN CheckRegistryRule(PCUNICODE_STRING KeyName) {
    if (!KeyName || !KeyName->Buffer) return FALSE;

    if (KeyName->Length < 4 * sizeof(WCHAR)) return FALSE;

    for (int i = 0; i < sizeof(RegistryBlockList) / sizeof(RegistryBlockList[0]); i++) {
        if (WildcardMatch(RegistryBlockList[i], KeyName->Buffer, KeyName->Length)) return TRUE;
    }
    return FALSE;
}

BOOLEAN CheckFileExtensionRule(PCUNICODE_STRING FileName) {
    if (!FileName || !FileName->Buffer) return FALSE;
    for (int i = 0; i < sizeof(DangerousExtensions) / sizeof(DangerousExtensions[0]); i++) {
        if (HasSuffix(FileName, DangerousExtensions[i])) return TRUE;
    }
    return FALSE;
}

BOOLEAN CheckProtectedPathRule(PCUNICODE_STRING FileName) {
    if (!FileName || !FileName->Buffer) return FALSE;

    if (WildcardMatch(L"*\\Windows\\System32\\config\\systemprofile*", FileName->Buffer, FileName->Length)) {
        return FALSE;
    }

    for (int i = 0; i < sizeof(ProtectedPaths) / sizeof(ProtectedPaths[0]); i++) {
        if (WildcardMatch(ProtectedPaths[i], FileName->Buffer, FileName->Length)) return TRUE;
    }
    return FALSE;
}

static BOOLEAN IsHighEntropy(PVOID Buffer, ULONG Length) {
    if (!Buffer || Length < 256) return FALSE;

    ULONG Histogram[256] = { 0 };
    PUCHAR Ptr = (PUCHAR)Buffer;
    ULONG ScanLen = (Length > 1024) ? 1024 : Length;

    __try {
        for (ULONG i = 0; i < ScanLen; i++) {
            Histogram[Ptr[i]]++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    ULONG MaxFreq = 0;
    for (int i = 0; i < 256; i++) {
        if (Histogram[i] > MaxFreq) MaxFreq = Histogram[i];
    }

    ULONG ExpectedAvg = ScanLen / 256;
    return (MaxFreq < (ExpectedAvg + HIGH_ENTROPY_THRESHOLD));
}

static BOOLEAN IsNaturallyCompressed(PCUNICODE_STRING FileName) {
    if (!FileName || !FileName->Buffer) return FALSE;
    for (int i = 0; i < sizeof(NaturallyCompressedExtensions) / sizeof(NaturallyCompressedExtensions[0]); i++) {
        if (HasSuffix(FileName, NaturallyCompressedExtensions[i])) return TRUE;
    }
    return FALSE;
}

static BOOLEAN IsNoisyRansomPath(PCUNICODE_STRING FileName) {
    if (!FileName || !FileName->Buffer) return FALSE;

    if (WildcardMatch(L"*\\Windows\\Temp\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Windows\\SystemTemp\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Windows\\Prefetch\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Windows\\Logs\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Profiles\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Program*\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\AppData\\Local\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\User Data\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*$Recycle.Bin*", FileName->Buffer, FileName->Length)) {
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN IsExplorerProcess(HANDLE ProcessId) {
    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;
    PUNICODE_STRING imageFileName = NULL;
    NTSTATUS status = GetProcessImageName(ProcessId, &imageFileName);
    BOOLEAN isExplorer = FALSE;
    if (NT_SUCCESS(status) && imageFileName && imageFileName->Buffer) {
        if (HasSuffix(imageFileName, L"\\explorer.exe")) isExplorer = TRUE;
        ExFreePool(imageFileName);
    }
    return isExplorer;
}

BOOLEAN CheckRansomActivity(HANDLE ProcessId, PUNICODE_STRING FileName, PVOID Buffer, ULONG Length, BOOLEAN IsWrite) {
    if (IsNoisyRansomPath(FileName)) return FALSE;

    if (!IsWrite) {
        if (IsExplorerProcess(ProcessId)) return FALSE;
    }

    LARGE_INTEGER Now = { 0 };
    KeQuerySystemTime(&Now);
    BOOLEAN Result = FALSE;
    BOOLEAN SuspiciousWrite = FALSE;

    if (IsWrite && Buffer && Length > 0) {
        if (!IsNaturallyCompressed(FileName) && IsHighEntropy(Buffer, Length)) {
            SuspiciousWrite = TRUE;
        }
    }
    if (IsWrite && !SuspiciousWrite) {
        return FALSE;
    }

    ExAcquireFastMutex(&GlobalData.TrackerMutex);

    PRANSOM_TRACKER Tracker = NULL;
    PRANSOM_TRACKER EmptySlot = NULL;

    for (int i = 0; i < MAX_TRACKERS; i++) {
        if (RansomTrackers[i].ProcessId == ProcessId) {
            Tracker = &RansomTrackers[i];
            break;
        }
        if (RansomTrackers[i].ProcessId == NULL && !EmptySlot) {
            EmptySlot = &RansomTrackers[i];
        }
    }

    if (!Tracker) {
        if (EmptySlot) {
            Tracker = EmptySlot;
            Tracker->ProcessId = ProcessId;
            Tracker->ActivityCount = 0;
            Tracker->LastActivityTime = Now;
        }
        else {
            ExReleaseFastMutex(&GlobalData.TrackerMutex);
            return FALSE;
        }
    }

    LARGE_INTEGER Diff;
    Diff.QuadPart = Now.QuadPart - Tracker->LastActivityTime.QuadPart;

    if (Diff.QuadPart > (RANSOM_TIME_WINDOW_MS * 10000LL)) {
        Tracker->ActivityCount = 0;
        Tracker->LastActivityTime = Now;
    }
    else {
        Tracker->LastActivityTime = Now;
    }
    ULONG Weight = 1;
    if (IsWrite) {
        Weight = SuspiciousWrite ? 2 : 1;
    }
    else {
        Weight = 2;
    }

    Tracker->ActivityCount += Weight;

    if (Tracker->ActivityCount >= RANSOM_COUNT_THRESHOLD) {
        Result = TRUE;
    }
    ExReleaseFastMutex(&GlobalData.TrackerMutex);
    return Result;
}

NTSTATUS SendMessageToUser(ULONG Code, ULONG Pid, PWCHAR Path, USHORT PathSize) {
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_UNSUCCESSFUL;

    PYAS_MESSAGE msg;
    RtlZeroMemory(&msg, sizeof(msg));
    msg.MessageCode = Code;
    msg.ProcessId = Pid;

    if (Path && PathSize > 0) {
        size_t MaxSize = sizeof(msg.Path) - sizeof(WCHAR);
        size_t BytesToCopy = PathSize;
        if (BytesToCopy > MaxSize) BytesToCopy = MaxSize;

        __try {
            RtlCopyMemory(msg.Path, Path, BytesToCopy);
            msg.Path[BytesToCopy / sizeof(WCHAR)] = L'\0';
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    if (!ExAcquireRundownProtection(&GlobalData.PortRundown)) {
        return STATUS_PORT_DISCONNECTED;
    }

    NTSTATUS status = STATUS_PORT_DISCONNECTED;
    if (GlobalData.ClientPort) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -(5 * 10000);
        status = FltSendMessage(GlobalData.FilterHandle, &GlobalData.ClientPort, &msg, sizeof(msg), NULL, NULL, &timeout);
    }

    ExReleaseRundownProtection(&GlobalData.PortRundown);
    return status;
}