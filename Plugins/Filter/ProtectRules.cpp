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
    L"\\Windows\\System32\\lsass.exe",
    L"\\Windows\\System32\\services.exe",
    L"\\Windows\\System32\\csrss.exe",
    L"\\Windows\\System32\\smss.exe",
    L"\\Windows\\System32\\wininit.exe",
    L"\\Windows\\System32\\winlogon.exe",
    L"\\Windows\\System32\\svchost.exe",
    L"\\Windows\\System32\\SearchIndexer.exe",
    L"\\Windows\\System32\\msiexec.exe",
    L"\\Windows\\System32\\TrustedInstaller.exe",
    L"\\Windows\\System32\\TiWorker.exe",
    L"\\Windows\\System32\\dism.exe",
    L"\\Windows\\System32\\dismhost.exe",
    L"\\Windows\\System32\\wuauclt.exe",
    L"\\Windows\\System32\\taskhostw.exe",
    L"\\Windows\\System32\\MoUsoCoreWorker.exe",
    L"\\Windows\\System32\\sppsvc.exe",
    L"\\Windows\\System32\\backgroundTaskHost.exe",
    L"\\Windows\\System32\\RuntimeBroker.exe",
    L"\\Windows\\System32\\ctfmon.exe",
    L"\\Windows\\System32\\smartscreen.exe"
};

const PCWSTR SafeProcessPatterns[] = {
    L"*\\Windows Defender\\MsMpEng.exe",
    L"*\\Windows Defender\\NisSrv.exe",
    L"*\\Windows Defender\\MsSense.exe",
    L"*\\Windows Defender Advanced Threat Protection\\MsSense.exe",
    L"*\\Microsoft\\EdgeUpdate\\*",
    L"*\\Google\\Update\\*"
};

const PCWSTR RegistryBlockList[] = {
    L"\\REGISTRY\\MACHINE\\BCD00000000\\*",
    L"\\REGISTRY\\MACHINE\\SAM\\*",
    L"\\REGISTRY\\MACHINE\\SECURITY\\*",
    L"\\REGISTRY\\USER\\*_Classes\\*\\shell\\open\\command\\*",
    L"\\REGISTRY\\USER\\S-1-*\\SOFTWARE\\NetWire\\*",
    L"\\REGISTRY\\USER\\S-1-*\\SOFTWARE\\Remcos*\\*",
    L"\\REGISTRY\\USER\\S-1-*\\SOFTWARE\\DC3_FEXEC\\*",
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
    L"*\\Image File Execution Options\\*"
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
    L".exe", L".dll", L".sys", L".mui",
    L".docx", L".xlsx", L".pptx", L".odt", L".ods"
};

const PCWSTR ProtectedPaths[] = {
    L"*\\PYAS.exe",
    L"*\\PYAS_Driver.sys",
    L"*\\ProgramData\\PYAS\\*.json",

    L"*\\Windows\\System32\\*.exe",
    L"*\\Windows\\System32\\*.dll",
    L"*\\Windows\\SysWOW64\\*.exe",
    L"*\\Windows\\SysWOW64\\*.dll",
    L"*\\Windows\\System32\\drivers\\etc\\hosts",

    L"*\\bootmgr",
    L"*\\boot.ini",
    L"*\\BOOTNXT",
    L"*\\EFI\\*",
    L"*\\Boot\\*",
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
    L"*\\COM?",
    L"*\\COM?\\*",
    L"*\\LPT?",
    L"*\\LPT?\\*",
    L"*\\evil*.exe",
    L"*\\OSDATA",
    L"*\\OSDATA\\*"
};

static BOOLEAN HasSuffix(PCUNICODE_STRING String, PCWSTR Suffix) {
    if (!String || !String->Buffer || !Suffix) return FALSE;

    SIZE_T SuffixLenBytes = 0;
    while (Suffix[SuffixLenBytes / sizeof(WCHAR)] != L'\0') {
        SuffixLenBytes += sizeof(WCHAR);
    }

    if (String->Length < SuffixLenBytes) return FALSE;

    UNICODE_STRING SuffixPart{};
    SuffixPart.Buffer = (PWCH)((PUCHAR)String->Buffer + String->Length - SuffixLenBytes);
    SuffixPart.Length = (USHORT)SuffixLenBytes;
    SuffixPart.MaximumLength = (USHORT)SuffixLenBytes;

    UNICODE_STRING TargetSuffix;
    RtlInitUnicodeString(&TargetSuffix, Suffix);

    return RtlEqualUnicodeString(&SuffixPart, &TargetSuffix, TRUE);
}

BOOLEAN WildcardMatch(PCWSTR Pattern, PCWSTR String, USHORT StringLengthBytes) {
    if (!Pattern || !String) return FALSE;

    PCWSTR mp = NULL;
    PCWSTR cp = NULL;
    PCWSTR StringEnd = (PCWSTR)((PUCHAR)String + StringLengthBytes);

    while ((PUCHAR)String < (PUCHAR)StringEnd) {
        WCHAR pChar = *Pattern;
        WCHAR sChar = *String;

        if (pChar == L'*') {
            if (!*++Pattern) return TRUE;
            mp = Pattern;
            cp = String + 1;
        }
        else if ((RtlDowncaseUnicodeChar(pChar) == RtlDowncaseUnicodeChar(sChar)) || pChar == L'?') {
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

    while (*Pattern == L'*') Pattern++;
    return !*Pattern && ((PUCHAR)String >= (PUCHAR)StringEnd);
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

    if (NT_SUCCESS(status) && imageFileName) {
        if (imageFileName->Buffer) {
            for (SIZE_T i = 0; i < sizeof(SafeSystemBinaries) / sizeof(SafeSystemBinaries[0]); i++) {
                if (HasSuffix(imageFileName, SafeSystemBinaries[i])) {
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
        ExFreePool(imageFileName);
    }

    return isTrusted;
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
    for (int i = 0; i < sizeof(RegistryBlockList) / sizeof(RegistryBlockList[0]); i++) {
        if (WildcardMatch(RegistryBlockList[i], KeyName->Buffer, KeyName->Length)) return TRUE;
    }
    return FALSE;
}

BOOLEAN CheckFileExtensionRule(PCUNICODE_STRING FileName) {
    if (!FileName || !FileName->Buffer) return FALSE;

    for (int i = 0; i < sizeof(DangerousExtensions) / sizeof(DangerousExtensions[0]); i++) {
        if (HasSuffix(FileName, DangerousExtensions[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN CheckProtectedPathRule(PCUNICODE_STRING FileName) {
    if (!FileName || !FileName->Buffer) return FALSE;

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
    if (MaxFreq < (ExpectedAvg + HIGH_ENTROPY_THRESHOLD)) {
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN IsNaturallyCompressed(PCUNICODE_STRING FileName) {
    if (!FileName || !FileName->Buffer) return FALSE;

    for (int i = 0; i < sizeof(NaturallyCompressedExtensions) / sizeof(NaturallyCompressedExtensions[0]); i++) {
        if (HasSuffix(FileName, NaturallyCompressedExtensions[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN IsNoisyRansomPath(PCUNICODE_STRING FileName) {
    if (!FileName || !FileName->Buffer) return FALSE;

    if (WildcardMatch(L"*\\Windows\\Temp\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\AppData\\Local\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Windows\\SystemTemp\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Program Files*\\*\\Temp\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*$Recycle.Bin*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\ProgramData\\Microsoft\\Windows Defender\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Program Files*\\Microsoft\\EdgeUpdate\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Program Files*\\Microsoft\\Edge\\*", FileName->Buffer, FileName->Length)) {
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN IsExplorerProcess(HANDLE ProcessId) {
    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;

    PUNICODE_STRING imageFileName = NULL;
    NTSTATUS status = GetProcessImageName(ProcessId, &imageFileName);
    BOOLEAN isExplorer = FALSE;

    if (NT_SUCCESS(status) && imageFileName) {
        if (imageFileName->Buffer) {
            if (HasSuffix(imageFileName, L"explorer.exe")) {
                isExplorer = TRUE;
            }
        }
        ExFreePool(imageFileName);
    }
    return isExplorer;
}

BOOLEAN CheckRansomActivity(HANDLE ProcessId, PUNICODE_STRING FileName, PVOID Buffer, ULONG Length, BOOLEAN IsWrite) {
    if (IsNoisyRansomPath(FileName)) return FALSE;

    if (!IsWrite) {
        if (IsExplorerProcess(ProcessId)) {
            return FALSE;
        }
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

    ExAcquireFastMutex(&GlobalData.TrackerMutex);

    if (IsWrite && !SuspiciousWrite) {
        ExReleaseFastMutex(&GlobalData.TrackerMutex);
        return FALSE;
    }

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

    LARGE_INTEGER Diff = { 0 };
    Diff.QuadPart = Now.QuadPart - Tracker->LastActivityTime.QuadPart;

    if (Diff.QuadPart > (RANSOM_TIME_WINDOW_MS * 10000LL)) {
        Tracker->ActivityCount = 0;
        Tracker->LastActivityTime = Now;
    }

    ULONG Weight = 1;
    if (IsWrite) {
        Weight = SuspiciousWrite ? 2 : 1;
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
        if (BytesToCopy > MaxSize) {
            BytesToCopy = MaxSize;
        }

        __try {
            RtlCopyMemory(msg.Path, Path, BytesToCopy);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_ACCESS_VIOLATION;
        }
        msg.Path[BytesToCopy / sizeof(WCHAR)] = L'\0';
    }

    if (!ExAcquireRundownProtection(&GlobalData.PortRundown)) {
        return STATUS_PORT_DISCONNECTED;
    }

    NTSTATUS status = STATUS_SUCCESS;

    if (GlobalData.ClientPort) {
        LARGE_INTEGER timeout{};
        timeout.QuadPart = -(5 * 10000);
        PFLT_PORT Port = GlobalData.ClientPort;

        status = FltSendMessage(GlobalData.FilterHandle, &Port, &msg, sizeof(msg), NULL, NULL, &timeout);
    }
    else {
        status = STATUS_PORT_DISCONNECTED;
    }

    ExReleaseRundownProtection(&GlobalData.PortRundown);
    return status;
}