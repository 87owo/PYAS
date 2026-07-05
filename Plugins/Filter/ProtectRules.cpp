#include "DriverCommon.h"

constexpr auto MAX_TRACKERS = 128;
constexpr auto TRUST_CACHE_SIZE = 128;
constexpr auto TRUST_CACHE_TTL_SEC = 300;

typedef struct _BEHAVIOR_TRACKER {
    PEPROCESS Process;
    PDYNAMIC_RULE Rule;
    LARGE_INTEGER ProcessCreateTime;
    ULONG ActivityCount;
    LARGE_INTEGER LastActivityTime;
} BEHAVIOR_TRACKER, * PBEHAVIOR_TRACKER;

typedef struct _TRUST_CACHE_ENTRY {
    PEPROCESS Process;
    LARGE_INTEGER ProcessCreateTime;
    BOOLEAN IsTrusted;
    LARGE_INTEGER CacheTime;
} TRUST_CACHE_ENTRY, * PTRUST_CACHE_ENTRY;

static BEHAVIOR_TRACKER BehaviorTrackers[MAX_TRACKERS];
static TRUST_CACHE_ENTRY TrustCache[TRUST_CACHE_SIZE];
static KSPIN_LOCK TrustCacheLock;
static BOOLEAN g_CacheInitialized = FALSE;

static ERESOURCE RuleLock;
static PDYNAMIC_RULE g_DynamicRules = NULL;
static PRULE_NODE g_ProcessTrustedPaths = NULL;

static BOOLEAN CheckRuleThreshold(PDYNAMIC_RULE Rule, HANDLE ProcessId);
BOOLEAN IsAddressInUnmappedMemory(HANDLE ProcessId, PVOID Address);

ULONG SafeGetPyasPid() {
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) return GlobalData.PyasPid;
    KIRQL OldIrql;
    KeAcquireSpinLock(&GlobalData.PidLock, &OldIrql);
    ULONG Pid = GlobalData.PyasPid;
    KeReleaseSpinLock(&GlobalData.PidLock, OldIrql);
    return Pid;
}

VOID SafeSetPyasPid(ULONG Pid) {
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) return;
    KIRQL OldIrql;
    KeAcquireSpinLock(&GlobalData.PidLock, &OldIrql);
    GlobalData.PyasPid = Pid;
    KeReleaseSpinLock(&GlobalData.PidLock, OldIrql);
}

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
    PRULE_NODE Check = *Head;
    while (Check) {
        if (RtlEqualUnicodeString(&Check->Pattern, RuleStr, TRUE)) return;
        Check = Check->Next;
    }
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

static VOID RemoveRule(PRULE_NODE* Head, PUNICODE_STRING RuleStr) {
    if (!RuleStr || !RuleStr->Buffer) return;
    PRULE_NODE Current = *Head;
    PRULE_NODE Previous = NULL;
    while (Current) {
        if (RtlEqualUnicodeString(&Current->Pattern, RuleStr, TRUE)) {
            PRULE_NODE ToDelete = Current;
            if (Previous) Previous->Next = Current->Next;
            else *Head = Current->Next;
            Current = Current->Next;
            if (ToDelete->Pattern.Buffer) PyasFree(ToDelete->Pattern.Buffer);
            PyasFree(ToDelete);
        }
        else {
            Previous = Current;
            Current = Current->Next;
        }
    }
}

static BOOLEAN HasSuffix(PCUNICODE_STRING String, PCWSTR Suffix) {
    if (!String || !String->Buffer || !Suffix) return FALSE;
    SIZE_T StringLenChars = String->Length / sizeof(WCHAR);
    SIZE_T SuffixLenChars = wcslen(Suffix);
    if (StringLenChars < SuffixLenChars) return FALSE;
    PCWSTR Ptr = String->Buffer + (StringLenChars - SuffixLenChars);
    for (SIZE_T i = 0; i < SuffixLenChars; i++) {
        if (RtlDowncaseUnicodeChar(Ptr[i]) != RtlDowncaseUnicodeChar(Suffix[i])) return FALSE;
    }
    return TRUE;
}

BOOLEAN WildcardMatch(PCWSTR Pattern, PCWSTR String, USHORT StringLengthBytes) {
    if (Pattern == NULL || String == NULL) return FALSE;
    USHORT StringLenChars = StringLengthBytes / sizeof(WCHAR);
    PCWSTR mp = NULL;
    PCWSTR cp = NULL;
    PCWSTR StringEnd = String + StringLenChars;

    while (String < StringEnd) {
        if (*Pattern == L'*') {
            mp = ++Pattern;
            cp = String + 1;
        }
        else if (*Pattern == L'?' || (RtlDowncaseUnicodeChar(*Pattern) == RtlDowncaseUnicodeChar(*String))) {
            Pattern++;
            String++;
        }
        else if (mp != NULL) {
            Pattern = mp;
            String = cp++;
        }
        else {
            return FALSE;
        }
    }
    while (*Pattern == L'*') Pattern++;
    return (*Pattern == L'\0') ? TRUE : FALSE;
}

static BOOLEAN MatchNodeListAny(PRULE_NODE Node, PCUNICODE_STRING Target) {
    if (!Node) return FALSE;
    if (!Target || !Target->Buffer) return FALSE;
    while (Node) {
        if (WildcardMatch(Node->Pattern.Buffer, Target->Buffer, Target->Length)) return TRUE;
        Node = Node->Next;
    }
    return FALSE;
}

static ULONG GetPatternSpecificity(PCUNICODE_STRING Pattern) {
    if (!Pattern || !Pattern->Buffer) return 0;
    ULONG Score = 1;
    ULONG Length = Pattern->Length / sizeof(WCHAR);
    for (ULONG i = 0; i < Length; i++) {
        if (Pattern->Buffer[i] != L'*' && Pattern->Buffer[i] != L'?') {
            Score++;
        }
    }
    return Score;
}

static ULONG GetNodeMatchSpecificity(PRULE_NODE Node, PCUNICODE_STRING Target) {
    if (!Node || !Target || !Target->Buffer) return 0;
    ULONG MaxScore = 0;
    while (Node) {
        if (WildcardMatch(Node->Pattern.Buffer, Target->Buffer, Target->Length)) {
            ULONG Score = GetPatternSpecificity(&Node->Pattern);
            if (Score > MaxScore) MaxScore = Score;
        }
        Node = Node->Next;
    }
    return MaxScore;
}

static BOOLEAN EvaluateNodeConflict(PRULE_NODE IncludeNode, PRULE_NODE ExcludeNode, PCUNICODE_STRING TargetString) {
    if (!TargetString) {
        if (IncludeNode) return FALSE;
        return TRUE;
    }

    ULONG IncludeScore = 0;
    ULONG ExcludeScore = 0;
    BOOLEAN HasInclude = (IncludeNode != NULL);
    BOOLEAN HasExclude = (ExcludeNode != NULL);

    if (HasInclude) {
        IncludeScore = GetNodeMatchSpecificity(IncludeNode, TargetString);
        if (IncludeScore == 0) return FALSE;
    }

    if (HasExclude) {
        ExcludeScore = GetNodeMatchSpecificity(ExcludeNode, TargetString);
        if (ExcludeScore > 0 && ExcludeScore >= (HasInclude ? IncludeScore : 1)) {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN MatchExtensionList(PRULE_NODE Node, PCUNICODE_STRING Target) {
    if (!Node) return FALSE;
    if (!Target || !Target->Buffer) return FALSE;
    while (Node) {
        if (HasSuffix(Target, Node->Pattern.Buffer)) return TRUE;
        Node = Node->Next;
    }
    return FALSE;
}

static ULONG ProcessJsonUnescape(PWCHAR Buffer, ULONG LengthChars) {
    if (!Buffer || LengthChars == 0) return 0;
    ULONG WriteIdx = 0, ReadIdx = 0;
    while (ReadIdx < LengthChars) {
        if (Buffer[ReadIdx] == L'\\' && (ReadIdx + 1 < LengthChars)) {
            WCHAR NextChar = Buffer[ReadIdx + 1];
            if (NextChar == L'\\' || NextChar == L'"' || NextChar == L'/') {
                Buffer[WriteIdx++] = NextChar; ReadIdx += 2;
            }
            else if (NextChar == L'n') { Buffer[WriteIdx++] = L'\n'; ReadIdx += 2; }
            else if (NextChar == L'r') { Buffer[WriteIdx++] = L'\r'; ReadIdx += 2; }
            else if (NextChar == L't') { Buffer[WriteIdx++] = L'\t'; ReadIdx += 2; }
            else { Buffer[WriteIdx++] = Buffer[ReadIdx++]; }
        }
        else { Buffer[WriteIdx++] = Buffer[ReadIdx++]; }
    }
    Buffer[WriteIdx] = L'\0';
    return WriteIdx * sizeof(WCHAR);
}

static VOID SkipWhitespace(PCHAR* Ptr, PCHAR End) {
    while (*Ptr < End) {
        char c = **Ptr;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') (*Ptr)++;
        else break;
    }
}

static ULONG ParseInt(PCHAR* Ptr, PCHAR End) {
    ULONG val = 0;
    SkipWhitespace(Ptr, End);
    while (*Ptr < End && **Ptr >= '0' && **Ptr <= '9') {
        val = val * 10 + (**Ptr - '0');
        (*Ptr)++;
    }
    return val;
}

static VOID ParseStringArray(PCHAR* Ptr, PCHAR End, PRULE_NODE* Head) {
    SkipWhitespace(Ptr, End);
    if (*Ptr >= End || **Ptr != '[') return;
    (*Ptr)++;
    while (*Ptr < End) {
        SkipWhitespace(Ptr, End);
        if (*Ptr >= End || **Ptr == ']') {
            if (*Ptr < End) (*Ptr)++;
            return;
        }
        if (**Ptr == '"') {
            PCHAR StartQuote = ++(*Ptr);
            BOOLEAN Escaped = FALSE;
            while (*Ptr < End) {
                if (**Ptr == '"' && !Escaped) break;
                Escaped = (**Ptr == '\\' && !Escaped);
                (*Ptr)++;
            }
            if (*Ptr < End && **Ptr == '"') {
                ULONG UTF8Len = (ULONG)(*Ptr - StartQuote);
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
                            AddRule(Head, &Us);
                            PyasFree(WideBuffer);
                        }
                    }
                }
                (*Ptr)++;
            }
        }
        else {
            (*Ptr)++;
        }
    }
}

static VOID ParseOperationsArray(PCHAR* Ptr, PCHAR End, PULONG Operations) {
    PRULE_NODE TempHead = NULL;
    ParseStringArray(Ptr, End, &TempHead);
    PRULE_NODE Node = TempHead;
    while (Node) {
        UNICODE_STRING WriteStr = RTL_CONSTANT_STRING(L"Write");
        UNICODE_STRING DeleteStr = RTL_CONSTANT_STRING(L"Delete");
        UNICODE_STRING CreateStr = RTL_CONSTANT_STRING(L"Create");
        UNICODE_STRING ExecuteStr = RTL_CONSTANT_STRING(L"Execute");
        UNICODE_STRING RenameStr = RTL_CONSTANT_STRING(L"Rename");
        UNICODE_STRING IoctlStr = RTL_CONSTANT_STRING(L"Ioctl");
        UNICODE_STRING VmReadStr = RTL_CONSTANT_STRING(L"VmRead");
        UNICODE_STRING VmWriteStr = RTL_CONSTANT_STRING(L"VmWrite");
        UNICODE_STRING TerminateStr = RTL_CONSTANT_STRING(L"Terminate");
        UNICODE_STRING SuspendResumeStr = RTL_CONSTANT_STRING(L"SuspendResume");
        UNICODE_STRING DuplicateHandleStr = RTL_CONSTANT_STRING(L"DuplicateHandle");
        UNICODE_STRING SetInformationStr = RTL_CONSTANT_STRING(L"SetInformation");

        if (RtlEqualUnicodeString(&Node->Pattern, &WriteStr, TRUE)) *Operations |= OP_WRITE;
        else if (RtlEqualUnicodeString(&Node->Pattern, &DeleteStr, TRUE)) *Operations |= OP_DELETE;
        else if (RtlEqualUnicodeString(&Node->Pattern, &CreateStr, TRUE)) *Operations |= OP_CREATE;
        else if (RtlEqualUnicodeString(&Node->Pattern, &ExecuteStr, TRUE)) *Operations |= OP_EXECUTE;
        else if (RtlEqualUnicodeString(&Node->Pattern, &RenameStr, TRUE)) *Operations |= OP_RENAME;
        else if (RtlEqualUnicodeString(&Node->Pattern, &IoctlStr, TRUE)) *Operations |= OP_IOCTL;
        else if (RtlEqualUnicodeString(&Node->Pattern, &VmReadStr, TRUE)) *Operations |= OP_VM_READ;
        else if (RtlEqualUnicodeString(&Node->Pattern, &VmWriteStr, TRUE)) *Operations |= OP_VM_WRITE;
        else if (RtlEqualUnicodeString(&Node->Pattern, &TerminateStr, TRUE)) *Operations |= OP_TERMINATE;
        else if (RtlEqualUnicodeString(&Node->Pattern, &SuspendResumeStr, TRUE)) *Operations |= OP_SUSPEND_RESUME;
        else if (RtlEqualUnicodeString(&Node->Pattern, &DuplicateHandleStr, TRUE)) *Operations |= OP_DUP_HANDLE;
        else if (RtlEqualUnicodeString(&Node->Pattern, &SetInformationStr, TRUE)) *Operations |= OP_SET_INFORMATION;

        Node = Node->Next;
    }
    FreeList(&TempHead);
}

static VOID ParseDynamicRules(PCHAR JsonContent, ULONG ContentLength) {
    PCHAR Ptr = JsonContent;
    PCHAR End = JsonContent + ContentLength;

    const char* TargetKey = "\"DynamicRules\"";
    SIZE_T KeyLen = strlen(TargetKey);

    while (Ptr < End - KeyLen) {
        if (RtlCompareMemory(Ptr, TargetKey, KeyLen) == KeyLen) {
            Ptr += KeyLen;
            SkipWhitespace(&Ptr, End);
            if (Ptr >= End || *Ptr != ':') continue;
            Ptr++;
            SkipWhitespace(&Ptr, End);
            if (Ptr >= End || *Ptr != '[') continue;
            Ptr++;

            while (Ptr < End) {
                SkipWhitespace(&Ptr, End);
                if (Ptr >= End || *Ptr == ']') break;
                if (*Ptr == '{') {
                    Ptr++;
                    PDYNAMIC_RULE Rule = (PDYNAMIC_RULE)PyasAllocate(sizeof(DYNAMIC_RULE));
                    if (Rule) {
                        RtlZeroMemory(Rule, sizeof(DYNAMIC_RULE));
                        while (Ptr < End) {
                            SkipWhitespace(&Ptr, End);
                            if (Ptr >= End || *Ptr == '}') {
                                if (Ptr < End) Ptr++;
                                break;
                            }
                            if (*Ptr == '"') {
                                PCHAR KeyStart = ++Ptr;
                                while (Ptr < End && *Ptr != '"') Ptr++;
                                ULONG KeyLenStr = (ULONG)(Ptr - KeyStart);
                                if (Ptr < End) Ptr++;
                                SkipWhitespace(&Ptr, End);
                                if (Ptr < End && *Ptr == ':') Ptr++;
                                SkipWhitespace(&Ptr, End);

                                if (KeyLenStr == 4 && RtlCompareMemory(KeyStart, "Code", 4) == 4) Rule->Code = ParseInt(&Ptr, End);
                                else if (KeyLenStr == 9 && RtlCompareMemory(KeyStart, "Threshold", 9) == 9) Rule->Threshold = ParseInt(&Ptr, End);
                                else if (KeyLenStr == 10 && RtlCompareMemory(KeyStart, "TimeWindow", 10) == 10) Rule->TimeWindow = ParseInt(&Ptr, End);
                                else if (KeyLenStr == 8 && RtlCompareMemory(KeyStart, "Category", 8) == 8) {
                                    if (*Ptr == '"') {
                                        Ptr++;
                                        if (RtlCompareMemory(Ptr, "Process", 7) == 7) Rule->Category = RuleCategoryProcess;
                                        else if (RtlCompareMemory(Ptr, "File", 4) == 4) Rule->Category = RuleCategoryFile;
                                        else if (RtlCompareMemory(Ptr, "Registry", 8) == 8) Rule->Category = RuleCategoryRegistry;
                                        else if (RtlCompareMemory(Ptr, "Device", 6) == 6) Rule->Category = RuleCategoryDevice;
                                        else if (RtlCompareMemory(Ptr, "Memory", 6) == 6) Rule->Category = RuleCategoryMemory;
                                        else if (RtlCompareMemory(Ptr, "Thread", 6) == 6) Rule->Category = RuleCategoryThread;
                                        while (Ptr < End && *Ptr != '"') Ptr++;
                                        if (Ptr < End) Ptr++;
                                    }
                                }
                                else if (KeyLenStr == 9 && RtlCompareMemory(KeyStart, "Initiator", 9) == 9) ParseStringArray(&Ptr, End, &Rule->Initiator);
                                else if (KeyLenStr == 16 && RtlCompareMemory(KeyStart, "InitiatorExclude", 16) == 16) ParseStringArray(&Ptr, End, &Rule->InitiatorExclude);
                                else if (KeyLenStr == 6 && RtlCompareMemory(KeyStart, "Target", 6) == 6) ParseStringArray(&Ptr, End, &Rule->Target);
                                else if (KeyLenStr == 13 && RtlCompareMemory(KeyStart, "TargetExclude", 13) == 13) ParseStringArray(&Ptr, End, &Rule->TargetExclude);
                                else if (KeyLenStr == 11 && RtlCompareMemory(KeyStart, "CommandLine", 11) == 11) ParseStringArray(&Ptr, End, &Rule->CommandLine);
                                else if (KeyLenStr == 10 && RtlCompareMemory(KeyStart, "Extensions", 10) == 10) ParseStringArray(&Ptr, End, &Rule->Extensions);
                                else if (KeyLenStr == 10 && RtlCompareMemory(KeyStart, "Operations", 10) == 10) ParseOperationsArray(&Ptr, End, &Rule->Operations);
                                else {
                                    BOOLEAN InQuote = FALSE, InArray = FALSE;
                                    while (Ptr < End) {
                                        if (*Ptr == '"' && *(Ptr - 1) != '\\') InQuote = !InQuote;
                                        else if (!InQuote && *Ptr == '[') InArray = TRUE;
                                        else if (!InQuote && *Ptr == ']') InArray = FALSE;
                                        else if (!InQuote && !InArray && (*Ptr == ',' || *Ptr == '}')) break;
                                        Ptr++;
                                    }
                                }
                            }
                            else Ptr++;
                        }
                        Rule->Next = g_DynamicRules;
                        g_DynamicRules = Rule;
                    }
                }
                else Ptr++;
            }
            break;
        }
        Ptr++;
    }
}

VOID InitializeRulesEngine() {
    ExInitializeResourceLite(&RuleLock);
    KeInitializeSpinLock(&TrustCacheLock);
    RtlZeroMemory(TrustCache, sizeof(TrustCache));
    RtlZeroMemory(BehaviorTrackers, sizeof(BehaviorTrackers));
    g_CacheInitialized = TRUE;
}

VOID UninitializeRulesEngine() {
    ExDeleteResourceLite(&RuleLock);
    g_CacheInitialized = FALSE;
}

VOID AddDynamicWhitelist(PUNICODE_STRING RuleStr) {
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&RuleLock, TRUE);
    AddRule(&g_ProcessTrustedPaths, RuleStr);

    KIRQL OldIrql;
    KeAcquireSpinLock(&TrustCacheLock, &OldIrql);
    RtlZeroMemory(TrustCache, sizeof(TrustCache));
    KeReleaseSpinLock(&TrustCacheLock, OldIrql);

    ExReleaseResourceLite(&RuleLock);
    KeLeaveCriticalRegion();
}

VOID RemoveDynamicWhitelist(PUNICODE_STRING RuleStr) {
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&RuleLock, TRUE);
    RemoveRule(&g_ProcessTrustedPaths, RuleStr);

    KIRQL OldIrql;
    KeAcquireSpinLock(&TrustCacheLock, &OldIrql);
    RtlZeroMemory(TrustCache, sizeof(TrustCache));
    KeReleaseSpinLock(&TrustCacheLock, OldIrql);

    ExReleaseResourceLite(&RuleLock);
    KeLeaveCriticalRegion();
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
        PathBufferSize = Info->DataLength + 1024;
        PathBuffer = (PWCHAR)PyasAllocate(PathBufferSize);
        if (PathBuffer) {
            RtlZeroMemory(PathBuffer, PathBufferSize);
            if (Info->DataLength > 0) RtlCopyMemory(PathBuffer, Info->Data, Info->DataLength);

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
                    if (Match) *SuffixStart = L'\0';
                }

                RtlStringCbCatW(PathBuffer, PathBufferSize, L"\\Rules\\Rules_Driver_P1.json");

                if (wcsncmp(PathBuffer, L"\\??\\", 4) != 0 && wcsncmp(PathBuffer, L"\\SystemRoot", 11) != 0 && wcsncmp(PathBuffer, L"\\DosDevices\\", 12) != 0) {
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
                    KeEnterCriticalRegion();
                    ExAcquireResourceExclusiveLite(&RuleLock, TRUE);
                    ParseDynamicRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart);
                    ExReleaseResourceLite(&RuleLock);
                    KeLeaveCriticalRegion();
                }
                PyasFree(FileBuffer);
            }
        }
        ZwClose(FileHandle);
    }
    if (PathBuffer) PyasFree(PathBuffer);
    return status;
}

NTSTATUS LoadRuleFile(PCUNICODE_STRING FilePath) {
    if (!FilePath || !FilePath->Buffer) return STATUS_INVALID_PARAMETER;

    NTSTATUS status = STATUS_SUCCESS;
    HANDLE FileHandle = NULL;
    IO_STATUS_BLOCK IoStatus = { 0 };
    OBJECT_ATTRIBUTES oa = { 0 };

    InitializeObjectAttributes(&oa, (PUNICODE_STRING)FilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
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
                    KeEnterCriticalRegion();
                    ExAcquireResourceExclusiveLite(&RuleLock, TRUE);
                    ParseDynamicRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart);
                    ExReleaseResourceLite(&RuleLock);
                    KeLeaveCriticalRegion();
                }
                PyasFree(FileBuffer);
            }
            else {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        ZwClose(FileHandle);
    }
    return status;
}

VOID ClearDynamicRules() {
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&RuleLock, TRUE);
    PDYNAMIC_RULE CurrentRule = g_DynamicRules;
    while (CurrentRule) {
        PDYNAMIC_RULE Next = CurrentRule->Next;
        FreeList(&CurrentRule->Initiator);
        FreeList(&CurrentRule->InitiatorExclude);
        FreeList(&CurrentRule->Target);
        FreeList(&CurrentRule->TargetExclude);
        FreeList(&CurrentRule->CommandLine);
        FreeList(&CurrentRule->Extensions);
        PyasFree(CurrentRule);
        CurrentRule = Next;
    }
    g_DynamicRules = NULL;
    ExReleaseResourceLite(&RuleLock);
    KeLeaveCriticalRegion();
}

VOID UnloadRules() {
    ClearDynamicRules();
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&RuleLock, TRUE);
    FreeList(&g_ProcessTrustedPaths);
    ExReleaseResourceLite(&RuleLock);
    KeLeaveCriticalRegion();
}

NTSTATUS GetProcessImageName(HANDLE ProcessId, PUNICODE_STRING* ImageName) {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_UNSUCCESSFUL;
    PEPROCESS Process = NULL;
    *ImageName = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(status)) return status;
    status = SeLocateProcessImageName(Process, ImageName);
    ObDereferenceObject(Process);
    return status;
}

BOOLEAN IsProcessTrusted(HANDLE ProcessId) {
    ULONG PyasPid = SafeGetPyasPid();
    if ((ULONG)(ULONG_PTR)ProcessId == PyasPid) return TRUE;
    if (ProcessId == (HANDLE)4) return TRUE;

    PEPROCESS Process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) return FALSE;

    LARGE_INTEGER createTime;
    createTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);

    if (g_CacheInitialized) {
        KIRQL OldIrql;
        KeAcquireSpinLock(&TrustCacheLock, &OldIrql);
        ULONG Hash = (((ULONG)(ULONG_PTR)ProcessId) >> 2) & (TRUST_CACHE_SIZE - 1);
        if (TrustCache[Hash].Process == Process && TrustCache[Hash].ProcessCreateTime.QuadPart == createTime.QuadPart) {
            LARGE_INTEGER Now;
            KeQuerySystemTime(&Now);
            if ((Now.QuadPart - TrustCache[Hash].CacheTime.QuadPart) < (TRUST_CACHE_TTL_SEC * 10000000LL)) {
                BOOLEAN cachedResult = TrustCache[Hash].IsTrusted;
                KeReleaseSpinLock(&TrustCacheLock, OldIrql);
                ObDereferenceObject(Process);
                return cachedResult;
            }
        }
        KeReleaseSpinLock(&TrustCacheLock, OldIrql);
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        ObDereferenceObject(Process);
        return FALSE;
    }

    PUNICODE_STRING imageFileName = NULL;
    NTSTATUS status = GetProcessImageName(ProcessId, &imageFileName);
    BOOLEAN isTrusted = FALSE;

    if (NT_SUCCESS(status) && imageFileName && imageFileName->Buffer) {
        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&RuleLock, TRUE);
        PRULE_NODE Node = g_ProcessTrustedPaths;
        while (Node) {
            if (WildcardMatch(Node->Pattern.Buffer, imageFileName->Buffer, imageFileName->Length)) {
                isTrusted = TRUE;
                break;
            }
            Node = Node->Next;
        }
        ExReleaseResourceLite(&RuleLock);
        KeLeaveCriticalRegion();
    }

    if (g_CacheInitialized) {
        KIRQL OldIrql;
        KeAcquireSpinLock(&TrustCacheLock, &OldIrql);
        ULONG Hash = (((ULONG)(ULONG_PTR)ProcessId) >> 2) & (TRUST_CACHE_SIZE - 1);
        TrustCache[Hash].Process = Process;
        TrustCache[Hash].ProcessCreateTime = createTime;
        TrustCache[Hash].IsTrusted = isTrusted;
        KeQuerySystemTime(&TrustCache[Hash].CacheTime);
        KeReleaseSpinLock(&TrustCacheLock, OldIrql);
    }

    if (imageFileName) ExFreePool(imageFileName);
    ObDereferenceObject(Process);
    return isTrusted;
}

static BOOLEAN CheckRuleThreshold(PDYNAMIC_RULE Rule, HANDLE ProcessId) {
    if (Rule->Threshold == 0) return TRUE;

    PEPROCESS Process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) return FALSE;

    LARGE_INTEGER Now;
    KeQuerySystemTime(&Now);
    LARGE_INTEGER createTime;
    createTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);
    BOOLEAN Triggered = FALSE;

    KIRQL OldIrql;
    KeAcquireSpinLock(&GlobalData.TrackerMutex, &OldIrql);

    PBEHAVIOR_TRACKER Tracker = NULL;
    PBEHAVIOR_TRACKER CandidateSlot = NULL;
    PBEHAVIOR_TRACKER LruSlot = &BehaviorTrackers[0];

    for (int i = 0; i < MAX_TRACKERS; i++) {
        PBEHAVIOR_TRACKER Current = &BehaviorTrackers[i];
        if (Current->LastActivityTime.QuadPart < LruSlot->LastActivityTime.QuadPart) LruSlot = Current;

        if (Current->Process == Process && Current->Rule == Rule && Current->ProcessCreateTime.QuadPart == createTime.QuadPart) {
            Tracker = Current;
            break;
        }

        BOOLEAN IsExpired = FALSE;
        if (Current->Process != NULL) {
            LARGE_INTEGER Diff;
            Diff.QuadPart = Now.QuadPart - Current->LastActivityTime.QuadPart;
            if (Diff.QuadPart > (Rule->TimeWindow * 10000LL)) IsExpired = TRUE;
        }
        if ((Current->Process == NULL || IsExpired) && !CandidateSlot) CandidateSlot = Current;
    }

    if (!Tracker) {
        Tracker = CandidateSlot ? CandidateSlot : LruSlot;
        Tracker->Process = Process;
        Tracker->Rule = Rule;
        Tracker->ProcessCreateTime = createTime;
        Tracker->ActivityCount = 0;
        Tracker->LastActivityTime = Now;
    }
    else {
        LARGE_INTEGER Diff;
        Diff.QuadPart = Now.QuadPart - Tracker->LastActivityTime.QuadPart;
        if (Diff.QuadPart > (Rule->TimeWindow * 10000LL)) Tracker->ActivityCount = 0;
        Tracker->LastActivityTime = Now;
    }

    Tracker->ActivityCount++;
    if (Tracker->ActivityCount >= Rule->Threshold) Triggered = TRUE;

    KeReleaseSpinLock(&GlobalData.TrackerMutex, OldIrql);
    ObDereferenceObject(Process);
    return Triggered;
}

BOOLEAN EvaluateProcessRule(HANDLE ProcessId, PCUNICODE_STRING TargetPath, PCUNICODE_STRING CommandLine, PULONG OutCode) {
    if (IsProcessTrusted(ProcessId)) return FALSE;
    PUNICODE_STRING InitiatorPath = NULL;
    GetProcessImageName(ProcessId, &InitiatorPath);

    BOOLEAN Blocked = FALSE;
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&RuleLock, TRUE);

    PDYNAMIC_RULE Rule = g_DynamicRules;
    while (Rule) {
        if (Rule->Category == RuleCategoryProcess && (Rule->Operations & OP_EXECUTE)) {
            BOOLEAN Match = TRUE;

            if (!EvaluateNodeConflict(Rule->Initiator, Rule->InitiatorExclude, InitiatorPath)) Match = FALSE;
            if (Match && !EvaluateNodeConflict(Rule->Target, Rule->TargetExclude, TargetPath)) Match = FALSE;
            if (Match && Rule->CommandLine && !MatchNodeListAny(Rule->CommandLine, CommandLine)) Match = FALSE;

            if (Match && CheckRuleThreshold(Rule, ProcessId)) {
                *OutCode = Rule->Code;
                Blocked = TRUE;
                break;
            }
        }
        Rule = Rule->Next;
    }

    ExReleaseResourceLite(&RuleLock);
    KeLeaveCriticalRegion();
    if (InitiatorPath) ExFreePool(InitiatorPath);
    return Blocked;
}

BOOLEAN EvaluateFileRule(HANDLE ProcessId, PCUNICODE_STRING TargetPath, ULONG Operation, PVOID WriteBuffer, ULONG WriteLength, PULONG OutCode) {
    UNREFERENCED_PARAMETER(WriteBuffer);
    UNREFERENCED_PARAMETER(WriteLength);

    if (IsProcessTrusted(ProcessId)) return FALSE;
    PUNICODE_STRING InitiatorPath = NULL;
    GetProcessImageName(ProcessId, &InitiatorPath);

    BOOLEAN Blocked = FALSE;
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&RuleLock, TRUE);

    PDYNAMIC_RULE Rule = g_DynamicRules;
    while (Rule) {
        if (Rule->Category == RuleCategoryFile && (Rule->Operations & Operation)) {
            BOOLEAN Match = TRUE;

            if (!EvaluateNodeConflict(Rule->Initiator, Rule->InitiatorExclude, InitiatorPath)) Match = FALSE;
            if (Match && !EvaluateNodeConflict(Rule->Target, Rule->TargetExclude, TargetPath)) Match = FALSE;
            if (Match && Rule->Extensions && !MatchExtensionList(Rule->Extensions, TargetPath)) Match = FALSE;

            if (Match && CheckRuleThreshold(Rule, ProcessId)) {
                *OutCode = Rule->Code;
                Blocked = TRUE;
                break;
            }
        }
        Rule = Rule->Next;
    }

    ExReleaseResourceLite(&RuleLock);
    KeLeaveCriticalRegion();
    if (InitiatorPath) ExFreePool(InitiatorPath);
    return Blocked;
}

BOOLEAN EvaluateRegistryRule(HANDLE ProcessId, PCUNICODE_STRING KeyName, ULONG Operation, PULONG OutCode) {
    if (IsProcessTrusted(ProcessId)) return FALSE;
    PUNICODE_STRING InitiatorPath = NULL;
    GetProcessImageName(ProcessId, &InitiatorPath);

    BOOLEAN Blocked = FALSE;
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&RuleLock, TRUE);

    PDYNAMIC_RULE Rule = g_DynamicRules;
    while (Rule) {
        if (Rule->Category == RuleCategoryRegistry && (Rule->Operations & Operation)) {
            BOOLEAN Match = TRUE;

            if (!EvaluateNodeConflict(Rule->Initiator, Rule->InitiatorExclude, InitiatorPath)) Match = FALSE;
            if (Match && !EvaluateNodeConflict(Rule->Target, Rule->TargetExclude, KeyName)) Match = FALSE;

            if (Match && CheckRuleThreshold(Rule, ProcessId)) {
                *OutCode = Rule->Code;
                Blocked = TRUE;
                break;
            }
        }
        Rule = Rule->Next;
    }

    ExReleaseResourceLite(&RuleLock);
    KeLeaveCriticalRegion();
    if (InitiatorPath) ExFreePool(InitiatorPath);
    return Blocked;
}

BOOLEAN EvaluateDeviceRule(HANDLE ProcessId, PULONG OutCode) {
    if (IsProcessTrusted(ProcessId)) return FALSE;
    PUNICODE_STRING InitiatorPath = NULL;
    GetProcessImageName(ProcessId, &InitiatorPath);

    BOOLEAN Blocked = FALSE;
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&RuleLock, TRUE);

    PDYNAMIC_RULE Rule = g_DynamicRules;
    while (Rule) {
        if (Rule->Category == RuleCategoryDevice && (Rule->Operations & OP_IOCTL)) {
            BOOLEAN Match = TRUE;

            if (!EvaluateNodeConflict(Rule->Initiator, Rule->InitiatorExclude, InitiatorPath)) Match = FALSE;

            if (Match && CheckRuleThreshold(Rule, ProcessId)) {
                *OutCode = Rule->Code;
                Blocked = TRUE;
                break;
            }
        }
        Rule = Rule->Next;
    }

    ExReleaseResourceLite(&RuleLock);
    KeLeaveCriticalRegion();
    if (InitiatorPath) ExFreePool(InitiatorPath);
    return Blocked;
}

static BOOLEAN EvaluateSourceTargetRule(HANDLE SourcePid, HANDLE TargetPid, RULE_CATEGORY Category, ULONG Operation, PULONG OutCode) {
    if (!OutCode || Operation == 0) return FALSE;
    if (IsProcessTrusted(SourcePid)) return FALSE;

    PUNICODE_STRING InitiatorPath = NULL;
    PUNICODE_STRING TargetPath = NULL;

    GetProcessImageName(SourcePid, &InitiatorPath);
    GetProcessImageName(TargetPid, &TargetPath);

    BOOLEAN Blocked = FALSE;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&RuleLock, TRUE);

    PDYNAMIC_RULE Rule = g_DynamicRules;
    while (Rule) {
        if (Rule->Category == Category && (Rule->Operations & Operation)) {
            BOOLEAN Match = TRUE;

            if (!EvaluateNodeConflict(Rule->Initiator, Rule->InitiatorExclude, InitiatorPath)) Match = FALSE;
            if (Match && !EvaluateNodeConflict(Rule->Target, Rule->TargetExclude, TargetPath)) Match = FALSE;

            if (Match && CheckRuleThreshold(Rule, SourcePid)) {
                *OutCode = Rule->Code;
                Blocked = TRUE;
                break;
            }
        }
        Rule = Rule->Next;
    }

    ExReleaseResourceLite(&RuleLock);
    KeLeaveCriticalRegion();

    if (InitiatorPath) ExFreePool(InitiatorPath);
    if (TargetPath) ExFreePool(TargetPath);

    return Blocked;
}

BOOLEAN EvaluateMemoryRule(HANDLE SourcePid, HANDLE TargetPid, ULONG Operation, PULONG OutCode) {
    return EvaluateSourceTargetRule(SourcePid, TargetPid, RuleCategoryMemory, Operation, OutCode);
}

BOOLEAN EvaluateProcessHandleRule(HANDLE SourcePid, HANDLE TargetPid, ULONG Operation, PULONG OutCode) {
    return EvaluateSourceTargetRule(SourcePid, TargetPid, RuleCategoryProcess, Operation, OutCode);
}

BOOLEAN EvaluateThreadRule(HANDLE SourcePid, HANDLE TargetPid, PVOID StartAddress, PULONG OutCode) {
    if (!IsAddressInUnmappedMemory(TargetPid, StartAddress)) return FALSE;

    PUNICODE_STRING InitiatorPath = NULL;
    PUNICODE_STRING TargetPath = NULL;

    GetProcessImageName(SourcePid, &InitiatorPath);
    GetProcessImageName(TargetPid, &TargetPath);

    BOOLEAN Blocked = FALSE;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&RuleLock, TRUE);

    PDYNAMIC_RULE Rule = g_DynamicRules;
    while (Rule) {
        if (Rule->Category == RuleCategoryThread && (Rule->Operations & OP_EXECUTE)) {
            BOOLEAN Match = TRUE;

            if (!EvaluateNodeConflict(Rule->Initiator, Rule->InitiatorExclude, InitiatorPath)) Match = FALSE;
            if (Match && !EvaluateNodeConflict(Rule->Target, Rule->TargetExclude, TargetPath)) Match = FALSE;

            if (Match && CheckRuleThreshold(Rule, SourcePid)) {
                *OutCode = Rule->Code;
                Blocked = TRUE;
                break;
            }
        }
        Rule = Rule->Next;
    }

    ExReleaseResourceLite(&RuleLock);
    KeLeaveCriticalRegion();

    if (InitiatorPath) ExFreePool(InitiatorPath);
    if (TargetPath) ExFreePool(TargetPath);

    return Blocked;
}

NTSTATUS SendMessageToUser(ULONG Code, ULONG Pid, PWCHAR Path, USHORT PathSize) {
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_UNSUCCESSFUL;
    if (!ExAcquireRundownProtection(&GlobalData.PortRundown)) return STATUS_PORT_DISCONNECTED;

    NTSTATUS status = STATUS_PORT_DISCONNECTED;

    if (GlobalData.ClientPort) {
        PPYAS_MESSAGE msg = (PPYAS_MESSAGE)PyasAllocate(sizeof(PYAS_MESSAGE));
        if (msg) {
            msg->MessageCode = Code;
            msg->ProcessId = Pid;

            if (Path && PathSize > 0) {
                size_t MaxSize = sizeof(msg->Path) - sizeof(WCHAR);
                size_t BytesToCopy = PathSize > MaxSize ? MaxSize : PathSize;

                __try {
                    RtlCopyMemory(msg->Path, Path, BytesToCopy);
                    msg->Path[BytesToCopy / sizeof(WCHAR)] = L'\0';
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    PyasFree(msg);
                    ExReleaseRundownProtection(&GlobalData.PortRundown);
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            LARGE_INTEGER timeout;
            timeout.QuadPart = (KeGetCurrentIrql() == PASSIVE_LEVEL) ? -(5 * 10000) : 0;
            status = FltSendMessage(GlobalData.FilterHandle, &GlobalData.ClientPort, msg, sizeof(PYAS_MESSAGE), NULL, NULL, &timeout);
            PyasFree(msg);
        }
        else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    ExReleaseRundownProtection(&GlobalData.PortRundown);
    return status;
}