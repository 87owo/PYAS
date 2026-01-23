#include "DriverCommon.h"

constexpr auto MAX_TRACKERS = 64;
constexpr auto RANSOM_TIME_WINDOW_MS = 3000;
constexpr auto RANSOM_COUNT_THRESHOLD = 5;
constexpr auto HIGH_ENTROPY_THRESHOLD = 10;

constexpr auto TRUST_CACHE_SIZE = 128;
constexpr auto TRUST_CACHE_TTL_SEC = 300;

typedef struct _RANSOM_TRACKER {
    HANDLE ProcessId;
    ULONG ActivityCount;
    LARGE_INTEGER LastActivityTime;
} RANSOM_TRACKER, * PRANSOM_TRACKER;

typedef struct _TRUST_CACHE_ENTRY {
    HANDLE ProcessId;
    BOOLEAN IsTrusted;
    LARGE_INTEGER CacheTime;
} TRUST_CACHE_ENTRY, * PTRUST_CACHE_ENTRY;

RANSOM_TRACKER RansomTrackers[MAX_TRACKERS];
TRUST_CACHE_ENTRY TrustCache[TRUST_CACHE_SIZE];
FAST_MUTEX TrustCacheLock;

static BOOLEAN g_CacheInitialized = FALSE;

ERESOURCE RuleLock;
PRULE_NODE g_RegistryBlockList = NULL;
PRULE_NODE g_RegistryTrustedList = NULL;
PRULE_NODE g_ProcessTrustedPaths = NULL;
PRULE_NODE g_ProcessExploitable = NULL;
PRULE_NODE g_FileProtectedPaths = NULL;
PRULE_NODE g_FileExceptionPaths = NULL;
PRULE_NODE g_FileRansomExts = NULL;

const PCWSTR Helper_NaturallyCompressedExtensions[] = {
    L".zip", L".7z", L".rar", L".tar", L".gz",
    L".jpg", L".jpeg", L".png", L".webp", L".gif",
    L".mp3", L".wav", L".aac", L".ogg", L".flac",
    L".mp4", L".avi", L".mov", L".wmv", L".mkv",
    L".docx", L".xlsx", L".pptx", L".pdf", L".wps",
    L".apk", L".jar", L".class", L".db", L".sqlite"
};

static VOID FreeList(PRULE_NODE* Head) {
    PRULE_NODE Current = *Head;
    while (Current) {
        PRULE_NODE Next = Current->Next;
        if (Current->Pattern.Buffer) PyasFree(Current->Pattern.Buffer);
        PyasFree(Current);
        Current = Next;
    }
    *Head = NULL;
}

static VOID AddRule(PRULE_NODE* Head, PUNICODE_STRING RuleStr) {
    if (!RuleStr || !RuleStr->Buffer) return;

    PRULE_NODE Node = (PRULE_NODE)PyasAllocate(sizeof(RULE_NODE));
    if (!Node) return;

    SIZE_T Size = RuleStr->Length + sizeof(WCHAR);
    Node->Pattern.Buffer = (PWCHAR)PyasAllocate(Size);
    if (!Node->Pattern.Buffer) {
        PyasFree(Node);
        return;
    }

    RtlCopyMemory(Node->Pattern.Buffer, RuleStr->Buffer, RuleStr->Length);
    Node->Pattern.Buffer[RuleStr->Length / sizeof(WCHAR)] = L'\0';
    Node->Pattern.Length = RuleStr->Length;
    Node->Pattern.MaximumLength = (USHORT)Size;

    Node->Next = *Head;
    *Head = Node;
}

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

static ULONG ProcessJsonUnescape(PWCHAR Buffer, ULONG LengthChars) {
    if (!Buffer || LengthChars == 0) return 0;

    ULONG WriteIdx = 0;
    ULONG ReadIdx = 0;

    while (ReadIdx < LengthChars) {
        if (Buffer[ReadIdx] == L'\\' && (ReadIdx + 1 < LengthChars)) {
            WCHAR NextChar = Buffer[ReadIdx + 1];
            if (NextChar == L'\\' || NextChar == L'"' || NextChar == L'/') {
                Buffer[WriteIdx++] = NextChar;
                ReadIdx += 2;
            }
            else if (NextChar == L'n') { Buffer[WriteIdx++] = L'\n'; ReadIdx += 2; }
            else if (NextChar == L'r') { Buffer[WriteIdx++] = L'\r'; ReadIdx += 2; }
            else if (NextChar == L't') { Buffer[WriteIdx++] = L'\t'; ReadIdx += 2; }
            else {
                Buffer[WriteIdx++] = Buffer[ReadIdx++];
            }
        }
        else {
            Buffer[WriteIdx++] = Buffer[ReadIdx++];
        }
    }

    Buffer[WriteIdx] = L'\0';
    return WriteIdx * sizeof(WCHAR);
}

static VOID SkipWhitespace(PCHAR* Ptr, PCHAR End) {
    while (*Ptr < End) {
        char c = **Ptr;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            (*Ptr)++;
        }
        else {
            break;
        }
    }
}

static VOID ParseAndLoadRules(PCHAR JsonContent, ULONG ContentLength, PCSTR KeyName, PRULE_NODE* ListHead) {
    if (!JsonContent || !KeyName || !ListHead) return;

    PCHAR Ptr = JsonContent;
    PCHAR End = JsonContent + ContentLength;
    SIZE_T KeyLen = 0;
    while (KeyName[KeyLen] != '\0') KeyLen++;

    while (Ptr < End) {
        if (*Ptr == '"') {
            if ((SIZE_T)(End - Ptr) > KeyLen && RtlCompareMemory(Ptr + 1, KeyName, KeyLen) == KeyLen) {
                if (*(Ptr + 1 + KeyLen) == '"') {
                    Ptr += 1 + KeyLen + 1;

                    SkipWhitespace(&Ptr, End);
                    if (Ptr >= End || *Ptr != ':') continue;
                    Ptr++;

                    SkipWhitespace(&Ptr, End);
                    if (Ptr >= End || *Ptr != '[') continue;
                    Ptr++;

                    while (Ptr < End) {
                        SkipWhitespace(&Ptr, End);
                        if (Ptr >= End) break;

                        if (*Ptr == ']') {
                            Ptr++;
                            return;
                        }

                        if (*Ptr == '"') {
                            PCHAR StartQuote = ++Ptr;
                            while (Ptr < End) {
                                if (*Ptr == '"' && *(Ptr - 1) != '\\') break;
                                Ptr++;
                            }

                            if (Ptr < End && *Ptr == '"') {
                                ULONG UTF8Len = (ULONG)(Ptr - StartQuote);
                                if (UTF8Len > 0) {
                                    ULONG WideSize = 0;
                                    RtlUTF8ToUnicodeN(NULL, 0, &WideSize, StartQuote, UTF8Len);

                                    if (WideSize > 0) {
                                        PWCHAR WideBuffer = (PWCHAR)PyasAllocate(WideSize + sizeof(WCHAR));
                                        if (WideBuffer) {
                                            ULONG ResultSize = 0;
                                            RtlUTF8ToUnicodeN(WideBuffer, WideSize, &ResultSize, StartQuote, UTF8Len);
                                            ULONG FinalSize = ProcessJsonUnescape(WideBuffer, ResultSize / sizeof(WCHAR));

                                            UNICODE_STRING Us;
                                            Us.Buffer = WideBuffer;
                                            Us.Length = (USHORT)FinalSize;
                                            Us.MaximumLength = (USHORT)(WideSize + sizeof(WCHAR));

                                            AddRule(ListHead, &Us);
                                            PyasFree(WideBuffer);
                                        }
                                    }
                                }
                                Ptr++;
                            }
                        }
                        else if (*Ptr == ',') {
                            Ptr++;
                        }
                        else {
                            Ptr++;
                        }
                    }
                    return;
                }
            }
        }
        Ptr++;
    }
}

NTSTATUS LoadRulesFromDisk(PUNICODE_STRING RegistryPath) {
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE FileHandle = NULL;
    IO_STATUS_BLOCK IoStatus = { 0 };
    OBJECT_ATTRIBUTES oa = { 0 };
    UNICODE_STRING ImagePathName;
    OBJECT_ATTRIBUTES RegOa = { 0 };
    HANDLE RegHandle = NULL;
    PKEY_VALUE_PARTIAL_INFORMATION Info = NULL;
    ULONG ResultLength = 0;
    PWCHAR PathBuffer = NULL;
    SIZE_T PathBufferSize = 0;
    UNICODE_STRING FinalPath = { 0 };

    RtlInitUnicodeString(&ImagePathName, L"ImagePath");
    ExInitializeResourceLite(&RuleLock);

    InitializeObjectAttributes(&RegOa, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&RegHandle, KEY_READ, &RegOa);
    if (!NT_SUCCESS(status)) return status;

    status = ZwQueryValueKey(RegHandle, &ImagePathName, KeyValuePartialInformation, NULL, 0, &ResultLength);
    if (status != STATUS_BUFFER_TOO_SMALL) {
        ZwClose(RegHandle);
        return status;
    }

    Info = (PKEY_VALUE_PARTIAL_INFORMATION)PyasAllocate(ResultLength);
    if (!Info) {
        ZwClose(RegHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryValueKey(RegHandle, &ImagePathName, KeyValuePartialInformation, Info, ResultLength, &ResultLength);
    ZwClose(RegHandle);
    if (!NT_SUCCESS(status)) {
        PyasFree(Info);
        return status;
    }

    if (Info->Type == REG_EXPAND_SZ || Info->Type == REG_SZ) {
        PathBufferSize = ResultLength + 1024;
        PathBuffer = (PWCHAR)PyasAllocate(PathBufferSize);

        if (PathBuffer) {
            RtlZeroMemory(PathBuffer, PathBufferSize);
            PWCHAR Src = (PWCHAR)Info->Data;

            if (NT_SUCCESS(RtlStringCbCopyW(PathBuffer, PathBufferSize, Src))) {
                PWCHAR LastSlash = NULL;
                PWCHAR Current = PathBuffer;
                while (*Current) {
                    if (*Current == L'\\') LastSlash = Current;
                    Current++;
                }

                if (LastSlash) {
                    *LastSlash = L'\0';

                    SIZE_T CurrentPathLen = wcslen(PathBuffer);
                    const WCHAR FilterSuffix[] = L"\\Filter";
                    SIZE_T FilterLen = (sizeof(FilterSuffix) / sizeof(WCHAR)) - 1;

                    if (CurrentPathLen >= FilterLen) {
                        PWCHAR SuffixStart = PathBuffer + CurrentPathLen - FilterLen;
                        BOOLEAN Match = TRUE;
                        for (SIZE_T i = 0; i < FilterLen; i++) {
                            if (RtlDowncaseUnicodeChar(SuffixStart[i]) != RtlDowncaseUnicodeChar(FilterSuffix[i])) {
                                Match = FALSE;
                                break;
                            }
                        }
                        if (Match) {
                            *SuffixStart = L'\0';
                        }
                    }

                    RtlStringCbCatW(PathBuffer, PathBufferSize, L"\\Rules\\Rules_Driver_P1.json");

                    if (wcsncmp(PathBuffer, L"\\??\\", 4) != 0 &&
                        wcsncmp(PathBuffer, L"\\SystemRoot", 11) != 0 &&
                        wcsncmp(PathBuffer, L"\\DosDevices\\", 12) != 0) {

                        PWCHAR TmpBuffer = (PWCHAR)PyasAllocate(PathBufferSize + 16);
                        if (TmpBuffer) {
                            RtlStringCbCopyW(TmpBuffer, PathBufferSize + 16, L"\\??\\");
                            RtlStringCbCatW(TmpBuffer, PathBufferSize + 16, PathBuffer);
                            PyasFree(PathBuffer);
                            PathBuffer = TmpBuffer;
                        }
                    }
                    RtlInitUnicodeString(&FinalPath, PathBuffer);
                }
            }
        }
    }
    PyasFree(Info);

    if (!FinalPath.Buffer) {
        if (PathBuffer) PyasFree(PathBuffer);
        return STATUS_UNSUCCESSFUL;
    }

    InitializeObjectAttributes(&oa, &FinalPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateFile(&FileHandle, GENERIC_READ | SYNCHRONIZE, &oa, &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (NT_SUCCESS(status)) {
        FILE_STANDARD_INFORMATION FileInfo = { 0 };
        status = ZwQueryInformationFile(FileHandle, &IoStatus, &FileInfo, sizeof(FileInfo), FileStandardInformation);

        if (NT_SUCCESS(status) && FileInfo.EndOfFile.LowPart > 0) {
            PVOID FileBuffer = PyasAllocate(FileInfo.EndOfFile.LowPart + 1);
            if (FileBuffer) {
                status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatus, FileBuffer, FileInfo.EndOfFile.LowPart, NULL, NULL);
                if (NT_SUCCESS(status)) {
                    ((PCHAR)FileBuffer)[FileInfo.EndOfFile.LowPart] = '\0';

                    ExAcquireResourceExclusiveLite(&RuleLock, TRUE);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_Registry_BlockList", &g_RegistryBlockList);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_Registry_TrustedList", &g_RegistryTrustedList);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_Process_TrustedPaths", &g_ProcessTrustedPaths);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_Process_ExploitableBlacklist", &g_ProcessExploitable);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_File_ProtectedPaths", &g_FileProtectedPaths);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_File_ExceptionPaths", &g_FileExceptionPaths);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_File_RansomwareExtensions", &g_FileRansomExts);
                    ExReleaseResourceLite(&RuleLock);
                }
                PyasFree(FileBuffer);
            }
        }
        ZwClose(FileHandle);
    }

    if (PathBuffer) PyasFree(PathBuffer);
    return status;
}

VOID UnloadRules() {
    ExAcquireResourceExclusiveLite(&RuleLock, TRUE);
    FreeList(&g_RegistryBlockList);
    FreeList(&g_RegistryTrustedList);
    FreeList(&g_ProcessTrustedPaths);
    FreeList(&g_ProcessExploitable);
    FreeList(&g_FileProtectedPaths);
    FreeList(&g_FileExceptionPaths);
    FreeList(&g_FileRansomExts);
    ExReleaseResourceLite(&RuleLock);
    ExDeleteResourceLite(&RuleLock);
}

NTSTATUS GetProcessImageName(HANDLE ProcessId, PUNICODE_STRING* ImageName) {
    NTSTATUS status;
    PEPROCESS Process = NULL;

    *ImageName = NULL;
    status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(status)) return status;

    status = SeLocateProcessImageName(Process, ImageName);
    ObDereferenceObject(Process);

    return status;
}

static VOID InitTrustCache() {
    if (g_CacheInitialized) return;
    ExInitializeFastMutex(&TrustCacheLock);
    RtlZeroMemory(TrustCache, sizeof(TrustCache));
    g_CacheInitialized = TRUE;
}

static BOOLEAN IsWindowsSystemApp(PCWSTR Buffer, USHORT Length) {
    if (WildcardMatch(L"*\\Windows\\SystemApps\\*", Buffer, Length)) return TRUE;
    if (WildcardMatch(L"*\\Windows\\ImmersiveControlPanel\\*", Buffer, Length)) return TRUE;
    if (WildcardMatch(L"*\\explorer.exe", Buffer, Length)) return TRUE;
    return FALSE;
}

BOOLEAN IsProcessTrusted(HANDLE ProcessId) {
    if ((ULONG)(ULONG_PTR)ProcessId == GlobalData.PyasPid) return TRUE;
    if (ProcessId == (HANDLE)4) return TRUE;

    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;

    if (g_CacheInitialized) {
        ExAcquireFastMutex(&TrustCacheLock);
        ULONG Hash = ((ULONG)(ULONG_PTR)ProcessId) & (TRUST_CACHE_SIZE - 1);
        if (TrustCache[Hash].ProcessId == ProcessId) {
            BOOLEAN cachedResult = TrustCache[Hash].IsTrusted;
            ExReleaseFastMutex(&TrustCacheLock);
            return cachedResult;
        }
        ExReleaseFastMutex(&TrustCacheLock);
    }
    else {
        InitTrustCache();
    }

    PUNICODE_STRING imageFileName = NULL;
    NTSTATUS status = GetProcessImageName(ProcessId, &imageFileName);
    BOOLEAN isTrusted = FALSE;

    if (NT_SUCCESS(status) && imageFileName && imageFileName->Buffer) {

        ExAcquireResourceSharedLite(&RuleLock, TRUE);

        PRULE_NODE Node = g_ProcessExploitable;
        while (Node) {
            if (WildcardMatch(Node->Pattern.Buffer, imageFileName->Buffer, imageFileName->Length)) {
                ExReleaseResourceLite(&RuleLock);
                goto cleanup;
            }
            Node = Node->Next;
        }

        if (IsWindowsSystemApp(imageFileName->Buffer, imageFileName->Length)) {
            isTrusted = TRUE;
            ExReleaseResourceLite(&RuleLock);
            goto cleanup;
        }

        Node = g_ProcessTrustedPaths;
        while (Node) {
            if (WildcardMatch(Node->Pattern.Buffer, imageFileName->Buffer, imageFileName->Length)) {
                isTrusted = TRUE;
                ExReleaseResourceLite(&RuleLock);
                goto cleanup;
            }
            Node = Node->Next;
        }

        ExReleaseResourceLite(&RuleLock);
    }

cleanup:
    if (g_CacheInitialized) {
        ExAcquireFastMutex(&TrustCacheLock);
        ULONG Hash = ((ULONG)(ULONG_PTR)ProcessId) & (TRUST_CACHE_SIZE - 1);
        TrustCache[Hash].ProcessId = ProcessId;
        TrustCache[Hash].IsTrusted = isTrusted;
        KeQuerySystemTime(&TrustCache[Hash].CacheTime);
        ExReleaseFastMutex(&TrustCacheLock);
    }

    if (imageFileName) ExFreePool(imageFileName);
    return isTrusted;
}

BOOLEAN IsCriticalSystemProcess(HANDLE ProcessId) {
    if ((ULONG)(ULONG_PTR)ProcessId == GlobalData.PyasPid) return TRUE;
    if (ProcessId == (HANDLE)4) return TRUE;

    return IsProcessTrusted(ProcessId);
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

    if (WildcardMatch(L"*{645FF040-5081-101B-9F08-00AA002F954E}\\DefaultIcon", KeyName->Buffer, KeyName->Length)) {
        return FALSE;
    }

    ExAcquireResourceSharedLite(&RuleLock, TRUE);

    PRULE_NODE AllowNode = g_RegistryTrustedList;
    while (AllowNode) {
        if (WildcardMatch(AllowNode->Pattern.Buffer, KeyName->Buffer, KeyName->Length)) {
            ExReleaseResourceLite(&RuleLock);
            return FALSE;
        }
        AllowNode = AllowNode->Next;
    }

    PRULE_NODE Node = g_RegistryBlockList;
    BOOLEAN Match = FALSE;
    while (Node) {
        if (WildcardMatch(Node->Pattern.Buffer, KeyName->Buffer, KeyName->Length)) {
            Match = TRUE;
            break;
        }
        Node = Node->Next;
    }
    ExReleaseResourceLite(&RuleLock);
    return Match;
}

BOOLEAN CheckFileExtensionRule(PCUNICODE_STRING FileName) {
    if (!FileName || !FileName->Buffer) return FALSE;

    ExAcquireResourceSharedLite(&RuleLock, TRUE);
    PRULE_NODE Node = g_FileRansomExts;
    BOOLEAN Match = FALSE;
    while (Node) {
        if (HasSuffix(FileName, Node->Pattern.Buffer)) {
            Match = TRUE;
            break;
        }
        Node = Node->Next;
    }
    ExReleaseResourceLite(&RuleLock);
    return Match;
}

BOOLEAN CheckProtectedPathRule(PCUNICODE_STRING FileName) {
    if (!FileName || !FileName->Buffer) return FALSE;

    if (WildcardMatch(L"*\\Windows\\System32\\config\\systemprofile*", FileName->Buffer, FileName->Length)) {
        return FALSE;
    }

    ExAcquireResourceSharedLite(&RuleLock, TRUE);

    PRULE_NODE ExNode = g_FileExceptionPaths;
    while (ExNode) {
        if (WildcardMatch(ExNode->Pattern.Buffer, FileName->Buffer, FileName->Length)) {
            ExReleaseResourceLite(&RuleLock);
            return FALSE; 
        }
        ExNode = ExNode->Next;
    }

    PRULE_NODE Node = g_FileProtectedPaths;
    BOOLEAN Match = FALSE;
    while (Node) {
        if (WildcardMatch(Node->Pattern.Buffer, FileName->Buffer, FileName->Length)) {
            Match = TRUE;
            break;
        }
        Node = Node->Next;
    }
    ExReleaseResourceLite(&RuleLock);
    return Match;
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
    for (int i = 0; i < sizeof(Helper_NaturallyCompressedExtensions) / sizeof(Helper_NaturallyCompressedExtensions[0]); i++) {
        if (HasSuffix(FileName, Helper_NaturallyCompressedExtensions[i])) return TRUE;
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

BOOLEAN CheckRansomActivity(HANDLE ProcessId, PUNICODE_STRING FileName, PVOID WriteBuffer, ULONG WriteLength, BOOLEAN IsWrite) {
    if (IsNoisyRansomPath(FileName)) {
        return FALSE;
    }

    if (!IsWrite) {
        if (IsExplorerProcess(ProcessId)) return FALSE;
    }

    BOOLEAN SuspiciousWrite = FALSE;
    if (IsWrite && WriteBuffer && WriteLength > 0) {
        if (!IsNaturallyCompressed(FileName) && IsHighEntropy(WriteBuffer, WriteLength)) {
            SuspiciousWrite = TRUE;
        }
    }

    if (IsWrite && !SuspiciousWrite) {
        return FALSE;
    }

    LARGE_INTEGER Now = { 0 };
    KeQuerySystemTime(&Now);
    BOOLEAN Result = FALSE;

    ExAcquireFastMutex(&GlobalData.TrackerMutex);

    PRANSOM_TRACKER Tracker = NULL;
    PRANSOM_TRACKER CandidateSlot = NULL;
    PRANSOM_TRACKER LruSlot = &RansomTrackers[0];

    for (int i = 0; i < MAX_TRACKERS; i++) {
        PRANSOM_TRACKER Current = &RansomTrackers[i];

        if (Current->LastActivityTime.QuadPart < LruSlot->LastActivityTime.QuadPart) {
            LruSlot = Current;
        }

        if (Current->ProcessId == ProcessId) {
            Tracker = Current;
            break;
        }

        BOOLEAN IsExpired = FALSE;
        if (Current->ProcessId != NULL) {
            LARGE_INTEGER Diff;
            Diff.QuadPart = Now.QuadPart - Current->LastActivityTime.QuadPart;
            if (Diff.QuadPart > (RANSOM_TIME_WINDOW_MS * 10000LL)) {
                IsExpired = TRUE;
            }
        }

        if ((Current->ProcessId == NULL || IsExpired) && !CandidateSlot) {
            CandidateSlot = Current;
        }
    }

    if (!Tracker) {
        if (CandidateSlot) {
            Tracker = CandidateSlot;
        }
        else {
            Tracker = LruSlot;
        }

        Tracker->ProcessId = ProcessId;
        Tracker->ActivityCount = 0;
        Tracker->LastActivityTime = Now;
    }
    else {
        LARGE_INTEGER Diff;
        Diff.QuadPart = Now.QuadPart - Tracker->LastActivityTime.QuadPart;

        if (Diff.QuadPart > (RANSOM_TIME_WINDOW_MS * 10000LL)) {
            Tracker->ActivityCount = 0;
        }
        Tracker->LastActivityTime = Now;
    }

    ULONG Weight = 2;
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