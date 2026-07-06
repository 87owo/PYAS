#include "DriverCommon.h"

constexpr auto MAX_TRACKERS = 128;
constexpr auto TRUST_CACHE_SIZE = 128;
constexpr auto TRUST_CACHE_TTL_SEC = 300;
constexpr auto MAX_RULE_FILE_SIZE = 4 * 1024 * 1024;

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

typedef struct _RULE_TERMINATION_WORK_ITEM {
    LIST_ENTRY Entry;
    PEPROCESS Process;
} RULE_TERMINATION_WORK_ITEM, * PRULE_TERMINATION_WORK_ITEM;

static BEHAVIOR_TRACKER BehaviorTrackers[MAX_TRACKERS];
static TRUST_CACHE_ENTRY TrustCache[TRUST_CACHE_SIZE];
static KSPIN_LOCK TrustCacheLock;
static BOOLEAN g_CacheInitialized = FALSE;

static ERESOURCE RuleLock;
static PDYNAMIC_RULE g_DynamicRules = NULL;
static PRULE_NODE g_ProcessTrustedPaths = NULL;
static LIST_ENTRY g_TerminationQueue;
static KSPIN_LOCK g_TerminationLock;
static KSEMAPHORE g_TerminationSemaphore;
static HANDLE g_TerminationWorkerHandle = NULL;
static volatile LONG g_TerminationStopping = 1;
static volatile LONG g_PendingTerminations = 0;
constexpr auto MAX_PENDING_TERMINATIONS = 128;

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

static BOOLEAN IsProtectedTerminationTarget(PEPROCESS Process) {
    if (!Process || Process == PsInitialSystemProcess) return TRUE;

    BOOLEAN IsConnectedClient = FALSE;
    KIRQL OldIrql;
    KeAcquireSpinLock(&GlobalData.PortMutex, &OldIrql);
    IsConnectedClient = GlobalData.PyasProcess == Process;
    KeReleaseSpinLock(&GlobalData.PortMutex, OldIrql);
    if (IsConnectedClient) return TRUE;

    PUNICODE_STRING ImagePath = NULL;
    NTSTATUS Status = SeLocateProcessImageName(Process, &ImagePath);
    if (!NT_SUCCESS(Status) || !ImagePath || !ImagePath->Buffer || ImagePath->Length == 0) {
        if (ImagePath) ExFreePool(ImagePath);
        return TRUE;
    }

    USHORT CharacterCount = ImagePath->Length / sizeof(WCHAR);
    LONG LastSeparator = -1;
    LONG ParentSeparator = -1;

    for (LONG Index = CharacterCount - 1; Index >= 0; Index--) {
        if (ImagePath->Buffer[Index] != L'\\') continue;
        if (LastSeparator < 0) LastSeparator = Index;
        else {
            ParentSeparator = Index;
            break;
        }
    }

    BOOLEAN Protected = TRUE;
    if (LastSeparator > 0 && ParentSeparator >= 0 && LastSeparator + 1 < CharacterCount) {
        UNICODE_STRING DirectoryName = {
            (USHORT)((LastSeparator - ParentSeparator - 1) * sizeof(WCHAR)),
            (USHORT)((LastSeparator - ParentSeparator - 1) * sizeof(WCHAR)),
            ImagePath->Buffer + ParentSeparator + 1
        };
        UNICODE_STRING FileName = {
            (USHORT)((CharacterCount - LastSeparator - 1) * sizeof(WCHAR)),
            (USHORT)((CharacterCount - LastSeparator - 1) * sizeof(WCHAR)),
            ImagePath->Buffer + LastSeparator + 1
        };
        UNICODE_STRING System32Name = RTL_CONSTANT_STRING(L"System32");

        if (!RtlEqualUnicodeString(&DirectoryName, &System32Name, TRUE)) {
            Protected = FALSE;
        }
        else {
            PCWSTR CriticalNames[] = {
                L"csrss.exe",
                L"smss.exe",
                L"wininit.exe",
                L"winlogon.exe",
                L"services.exe",
                L"lsass.exe",
                L"svchost.exe",
                L"fontdrvhost.exe",
                L"conhost.exe"
            };

            Protected = FALSE;
            for (ULONG Index = 0; Index < RTL_NUMBER_OF(CriticalNames); Index++) {
                UNICODE_STRING CriticalName;
                RtlInitUnicodeString(&CriticalName, CriticalNames[Index]);
                if (RtlEqualUnicodeString(&FileName, &CriticalName, TRUE)) {
                    Protected = TRUE;
                    break;
                }
            }
        }
    }

    ExFreePool(ImagePath);
    return Protected;
}

static VOID ReleaseRuleTerminationWork(PRULE_TERMINATION_WORK_ITEM Work) {
    if (!Work) return;
    if (Work->Process) ObDereferenceObject(Work->Process);
    PyasFree(Work);
    InterlockedDecrement(&g_PendingTerminations);
}

static PRULE_TERMINATION_WORK_ITEM PopRuleTerminationWork() {
    PRULE_TERMINATION_WORK_ITEM Work = NULL;

    KIRQL OldIrql;
    KeAcquireSpinLock(&g_TerminationLock, &OldIrql);
    if (!IsListEmpty(&g_TerminationQueue)) {
        PLIST_ENTRY Entry = RemoveHeadList(&g_TerminationQueue);
        Work = CONTAINING_RECORD(Entry, RULE_TERMINATION_WORK_ITEM, Entry);
    }
    KeReleaseSpinLock(&g_TerminationLock, OldIrql);
    return Work;
}

static VOID CancelRuleTerminationWork() {
    for (;;) {
        PRULE_TERMINATION_WORK_ITEM Work = PopRuleTerminationWork();
        if (!Work) break;
        ReleaseRuleTerminationWork(Work);
    }
}

static VOID TerminateRuleProcess(PEPROCESS Process) {
    if (IsProtectedTerminationTarget(Process)) return;

    HANDLE ProcessHandle = NULL;
    NTSTATUS Status = ObOpenObjectByPointer(
        Process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_TERMINATE,
        *PsProcessType,
        KernelMode,
        &ProcessHandle
    );

    if (!NT_SUCCESS(Status)) return;
    ZwTerminateProcess(ProcessHandle, STATUS_ACCESS_DENIED);
    ZwClose(ProcessHandle);
}

static VOID RuleTerminationWorkerThread(PVOID Parameter) {
    UNREFERENCED_PARAMETER(Parameter);

    for (;;) {
        KeWaitForSingleObject(
            &g_TerminationSemaphore,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );

        if (InterlockedCompareExchange(&g_TerminationStopping, 0, 0) != 0) {
            CancelRuleTerminationWork();
            break;
        }

        PRULE_TERMINATION_WORK_ITEM Work = PopRuleTerminationWork();
        if (!Work) continue;
        TerminateRuleProcess(Work->Process);
        ReleaseRuleTerminationWork(Work);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static NTSTATUS StartRuleTerminationWorker() {
    if (g_TerminationWorkerHandle) return STATUS_SUCCESS;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(
        &ObjectAttributes,
        NULL,
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    return PsCreateSystemThread(
        &g_TerminationWorkerHandle,
        SYNCHRONIZE,
        &ObjectAttributes,
        NULL,
        NULL,
        RuleTerminationWorkerThread,
        NULL
    );
}

static VOID StopRuleTerminationWorker() {
    CancelRuleTerminationWork();
    if (!g_TerminationWorkerHandle) return;

    KeReleaseSemaphore(&g_TerminationSemaphore, IO_NO_INCREMENT, 1, FALSE);
    ZwWaitForSingleObject(g_TerminationWorkerHandle, FALSE, NULL);
    ZwClose(g_TerminationWorkerHandle);
    g_TerminationWorkerHandle = NULL;
}

VOID QueueRuleProcessTermination(HANDLE ProcessId, BOOLEAN Kill) {
    if (!Kill || !ProcessId || (ULONG_PTR)ProcessId <= 4) return;
    if (KeGetCurrentIrql() > APC_LEVEL) return;
    if (InterlockedCompareExchange(&g_TerminationStopping, 0, 0) != 0) return;

    PEPROCESS Process = NULL;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) return;

    PRULE_TERMINATION_WORK_ITEM Work = (PRULE_TERMINATION_WORK_ITEM)PyasAllocate(sizeof(RULE_TERMINATION_WORK_ITEM));
    if (!Work) {
        ObDereferenceObject(Process);
        return;
    }

    RtlZeroMemory(Work, sizeof(*Work));
    Work->Process = Process;

    LONG Pending = InterlockedIncrement(&g_PendingTerminations);
    if (Pending > MAX_PENDING_TERMINATIONS) {
        ReleaseRuleTerminationWork(Work);
        return;
    }

    KIRQL OldIrql;
    KeAcquireSpinLock(&g_TerminationLock, &OldIrql);
    if (InterlockedCompareExchange(&g_TerminationStopping, 0, 0) != 0) {
        KeReleaseSpinLock(&g_TerminationLock, OldIrql);
        ReleaseRuleTerminationWork(Work);
        return;
    }

    InsertTailList(&g_TerminationQueue, &Work->Entry);
    KeReleaseSpinLock(&g_TerminationLock, OldIrql);
    KeReleaseSemaphore(&g_TerminationSemaphore, IO_NO_INCREMENT, 1, FALSE);
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

static VOID FreeDynamicRule(PDYNAMIC_RULE Rule) {
    if (!Rule) return;

    FreeList(&Rule->Initiator);
    FreeList(&Rule->InitiatorExclude);
    FreeList(&Rule->InitiatorParent);
    FreeList(&Rule->InitiatorParentExclude);
    FreeList(&Rule->InitiatorProcessTree);
    FreeList(&Rule->InitiatorProcessTreeExclude);
    FreeList(&Rule->Target);
    FreeList(&Rule->TargetExclude);
    FreeList(&Rule->TargetProcessTree);
    FreeList(&Rule->TargetProcessTreeExclude);
    FreeList(&Rule->Creator);
    FreeList(&Rule->CreatorExclude);
    FreeList(&Rule->Parent);
    FreeList(&Rule->ParentExclude);
    FreeList(&Rule->CommandLine);
    FreeList(&Rule->CommandLineExclude);
    FreeList(&Rule->Extensions);
    PyasFree(Rule);
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

static ULONGLONG ParseUnsigned64(PCHAR* Ptr, PCHAR End) {
    ULONGLONG Value = 0;
    ULONG Base = 10;

    SkipWhitespace(Ptr, End);

    if (*Ptr + 2 <= End && (*Ptr)[0] == '0' && ((*Ptr)[1] == 'x' || (*Ptr)[1] == 'X')) {
        Base = 16;
        *Ptr += 2;
    }

    while (*Ptr < End) {
        CHAR Character = **Ptr;
        ULONG Digit = 0;

        if (Character >= '0' && Character <= '9') Digit = Character - '0';
        else if (Base == 16 && Character >= 'a' && Character <= 'f') Digit = Character - 'a' + 10;
        else if (Base == 16 && Character >= 'A' && Character <= 'F') Digit = Character - 'A' + 10;
        else break;

        if (Digit >= Base) break;
        Value = Value * Base + Digit;
        (*Ptr)++;
    }

    return Value;
}

static ULONG ParseInt(PCHAR* Ptr, PCHAR End) {
    ULONGLONG Value = ParseUnsigned64(Ptr, End);
    return Value > MAXULONG ? MAXULONG : (ULONG)Value;
}

static BOOLEAN ParseBoolean(PCHAR* Ptr, PCHAR End, PBOOLEAN Value) {
    SkipWhitespace(Ptr, End);
    if (!Value) return FALSE;

    if (*Ptr + 4 <= End && RtlCompareMemory(*Ptr, "true", 4) == 4) {
        *Value = TRUE;
        *Ptr += 4;
        return TRUE;
    }

    if (*Ptr + 5 <= End && RtlCompareMemory(*Ptr, "false", 5) == 5) {
        *Value = FALSE;
        *Ptr += 5;
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN ParseStringValue(PCHAR* Ptr, PCHAR End, PCHAR Buffer, ULONG BufferSize) {
    SkipWhitespace(Ptr, End);
    if (!Buffer || BufferSize == 0 || *Ptr >= End || **Ptr != '"') return FALSE;

    (*Ptr)++;
    ULONG Length = 0;
    BOOLEAN Escaped = FALSE;

    while (*Ptr < End) {
        CHAR Character = **Ptr;
        if (Character == '"' && !Escaped) break;

        if (Length + 1 < BufferSize) {
            Buffer[Length++] = Character;
        }

        if (Character == '\\' && !Escaped) Escaped = TRUE;
        else Escaped = FALSE;
        (*Ptr)++;
    }

    if (*Ptr >= End || **Ptr != '"') return FALSE;
    (*Ptr)++;
    Buffer[Length] = '\0';
    return TRUE;
}

static VOID SkipJsonValue(PCHAR* Ptr, PCHAR End) {
    SkipWhitespace(Ptr, End);
    if (*Ptr >= End) return;

    if (**Ptr == '"') {
        CHAR Buffer[2] = { 0 };
        ParseStringValue(Ptr, End, Buffer, sizeof(Buffer));
        return;
    }

    if (**Ptr == '[' || **Ptr == '{') {
        CHAR Open = **Ptr;
        CHAR Close = Open == '[' ? ']' : '}';
        LONG Depth = 0;
        BOOLEAN InString = FALSE;
        BOOLEAN Escaped = FALSE;

        while (*Ptr < End) {
            CHAR Character = **Ptr;

            if (InString) {
                if (Character == '"' && !Escaped) InString = FALSE;
                if (Character == '\\' && !Escaped) Escaped = TRUE;
                else Escaped = FALSE;
                (*Ptr)++;
                continue;
            }

            if (Character == '"') InString = TRUE;
            else if (Character == Open) Depth++;
            else if (Character == Close) {
                Depth--;
                (*Ptr)++;
                if (Depth == 0) return;
                continue;
            }

            (*Ptr)++;
        }
        return;
    }

    while (*Ptr < End && **Ptr != ',' && **Ptr != '}') {
        (*Ptr)++;
    }
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

        if (**Ptr != '"') {
            (*Ptr)++;
            continue;
        }

        PCHAR StartQuote = ++(*Ptr);
        BOOLEAN Escaped = FALSE;

        while (*Ptr < End) {
            CHAR Character = **Ptr;
            if (Character == '"' && !Escaped) break;
            if (Character == '\\' && !Escaped) Escaped = TRUE;
            else Escaped = FALSE;
            (*Ptr)++;
        }

        if (*Ptr >= End || **Ptr != '"') return;

        ULONG Utf8Length = (ULONG)(*Ptr - StartQuote);
        if (Utf8Length > 0) {
            ULONG WideSize = 0;
            RtlUTF8ToUnicodeN(NULL, 0, &WideSize, StartQuote, Utf8Length);

            if (WideSize > 0 && WideSize <= 0xFFFC) {
                PWCHAR WideBuffer = (PWCHAR)PyasAllocate(WideSize + sizeof(WCHAR));

                if (WideBuffer) {
                    ULONG ResultSize = 0;
                    RtlZeroMemory(WideBuffer, WideSize + sizeof(WCHAR));
                    RtlUTF8ToUnicodeN(WideBuffer, WideSize, &ResultSize, StartQuote, Utf8Length);
                    ULONG FinalSize = ProcessJsonUnescape(WideBuffer, ResultSize / sizeof(WCHAR));

                    UNICODE_STRING Value;
                    Value.Buffer = WideBuffer;
                    Value.Length = (USHORT)FinalSize;
                    Value.MaximumLength = (USHORT)(WideSize + sizeof(WCHAR));
                    AddRule(Head, &Value);
                    PyasFree(WideBuffer);
                }
            }
        }

        (*Ptr)++;
    }
}

static BOOLEAN RuleNodeEquals(PRULE_NODE Node, PCWSTR Value) {
    UNICODE_STRING Target;
    RtlInitUnicodeString(&Target, Value);
    return Node && RtlEqualUnicodeString(&Node->Pattern, &Target, TRUE);
}

static BOOLEAN ParseHandleTypesArray(PCHAR* Ptr, PCHAR End, PULONG HandleTypes) {
    PRULE_NODE Values = NULL;
    ParseStringArray(Ptr, End, &Values);

    BOOLEAN Valid = Values != NULL;
    for (PRULE_NODE Node = Values; Node; Node = Node->Next) {
        if (RuleNodeEquals(Node, L"Create")) *HandleTypes |= PYAS_HANDLE_CREATE;
        else if (RuleNodeEquals(Node, L"Duplicate")) *HandleTypes |= PYAS_HANDLE_DUPLICATE;
        else Valid = FALSE;
    }

    FreeList(&Values);
    return Valid;
}

static BOOLEAN ParseObjectTypesArray(PCHAR* Ptr, PCHAR End, PULONG ObjectTypes) {
    PRULE_NODE Values = NULL;
    ParseStringArray(Ptr, End, &Values);

    BOOLEAN Valid = Values != NULL;
    for (PRULE_NODE Node = Values; Node; Node = Node->Next) {
        if (RuleNodeEquals(Node, L"Process")) *ObjectTypes |= PYAS_OBJECT_PROCESS;
        else if (RuleNodeEquals(Node, L"Thread")) *ObjectTypes |= PYAS_OBJECT_THREAD;
        else Valid = FALSE;
    }

    FreeList(&Values);
    return Valid;
}

static BOOLEAN ParseThreadMemoryTypesArray(PCHAR* Ptr, PCHAR End, PULONG MemoryTypes) {
    PRULE_NODE Values = NULL;
    ParseStringArray(Ptr, End, &Values);

    BOOLEAN Valid = Values != NULL;
    for (PRULE_NODE Node = Values; Node; Node = Node->Next) {
        if (RuleNodeEquals(Node, L"Private")) *MemoryTypes |= PYAS_MEMORY_PRIVATE;
        else if (RuleNodeEquals(Node, L"Mapped")) *MemoryTypes |= PYAS_MEMORY_MAPPED;
        else if (RuleNodeEquals(Node, L"Image")) *MemoryTypes |= PYAS_MEMORY_IMAGE;
        else Valid = FALSE;
    }

    FreeList(&Values);
    return Valid;
}

static BOOLEAN ParseThreadMemoryProtectionsArray(PCHAR* Ptr, PCHAR End, PULONG Protections) {
    PRULE_NODE Values = NULL;
    ParseStringArray(Ptr, End, &Values);

    BOOLEAN Valid = Values != NULL;
    for (PRULE_NODE Node = Values; Node; Node = Node->Next) {
        if (RuleNodeEquals(Node, L"Execute")) *Protections |= PYAS_PROTECT_EXECUTE;
        else if (RuleNodeEquals(Node, L"ExecuteWrite")) *Protections |= PYAS_PROTECT_EXECUTE_WRITE;
        else Valid = FALSE;
    }

    FreeList(&Values);
    return Valid;
}

static RULE_TRI_STATE ParseTriState(PCHAR* Ptr, PCHAR End, PBOOLEAN Parsed) {
    if (Parsed) *Parsed = FALSE;

    BOOLEAN Value = FALSE;
    if (!ParseBoolean(Ptr, End, &Value)) return RuleTriAny;
    if (Parsed) *Parsed = TRUE;
    return Value ? RuleTriTrue : RuleTriFalse;
}

static RULE_OPERATION_MATCH ParseOperationMatch(PCHAR* Ptr, PCHAR End, PBOOLEAN Parsed) {
    if (Parsed) *Parsed = FALSE;

    CHAR Value[16] = { 0 };
    if (!ParseStringValue(Ptr, End, Value, sizeof(Value))) return RuleOperationAny;
    if (strcmp(Value, "Any") == 0) {
        if (Parsed) *Parsed = TRUE;
        return RuleOperationAny;
    }
    if (strcmp(Value, "All") == 0) {
        if (Parsed) *Parsed = TRUE;
        return RuleOperationAll;
    }
    return RuleOperationAny;
}

static BOOLEAN ParseOperationsArray(PCHAR* Ptr, PCHAR End, PULONG Operations) {
    PRULE_NODE Values = NULL;
    ParseStringArray(Ptr, End, &Values);

    BOOLEAN Valid = Values != NULL;
    for (PRULE_NODE Node = Values; Node; Node = Node->Next) {
        if (RuleNodeEquals(Node, L"Write")) *Operations |= OP_WRITE;
        else if (RuleNodeEquals(Node, L"Delete")) *Operations |= OP_DELETE;
        else if (RuleNodeEquals(Node, L"Create")) *Operations |= OP_CREATE;
        else if (RuleNodeEquals(Node, L"Execute")) *Operations |= OP_EXECUTE;
        else if (RuleNodeEquals(Node, L"Rename")) *Operations |= OP_RENAME;
        else if (RuleNodeEquals(Node, L"Ioctl")) *Operations |= OP_IOCTL;
        else if (RuleNodeEquals(Node, L"VmRead")) *Operations |= OP_VM_READ;
        else if (RuleNodeEquals(Node, L"VmWrite")) {
            *Operations |= OP_VM_WRITE | OP_VM_OPERATION | OP_CREATE_THREAD | OP_THREAD_SET_CONTEXT;
        }
        else if (RuleNodeEquals(Node, L"WriteMemory")) *Operations |= OP_VM_WRITE;
        else if (RuleNodeEquals(Node, L"VmOperation")) *Operations |= OP_VM_OPERATION;
        else if (RuleNodeEquals(Node, L"CreateThread") || RuleNodeEquals(Node, L"CreateRemoteThread")) {
            *Operations |= OP_CREATE_THREAD;
        }
        else if (RuleNodeEquals(Node, L"SetThreadContext")) *Operations |= OP_THREAD_SET_CONTEXT;
        else if (RuleNodeEquals(Node, L"SetThreadToken")) *Operations |= OP_THREAD_SET_TOKEN;
        else if (RuleNodeEquals(Node, L"Terminate")) *Operations |= OP_TERMINATE;
        else if (RuleNodeEquals(Node, L"SuspendResume")) *Operations |= OP_SUSPEND_RESUME;
        else if (RuleNodeEquals(Node, L"DuplicateHandle")) *Operations |= OP_DUP_HANDLE;
        else if (RuleNodeEquals(Node, L"SetInformation")) *Operations |= OP_SET_INFORMATION;
        else if (RuleNodeEquals(Node, L"CreateProcess")) *Operations |= OP_CREATE_PROCESS;
        else if (RuleNodeEquals(Node, L"ImageLoad")) *Operations |= OP_IMAGE_LOAD;
        else if (RuleNodeEquals(Node, L"Impersonate")) *Operations |= OP_IMPERSONATE;
        else Valid = FALSE;
    }

    FreeList(&Values);
    return Valid;
}

static BOOLEAN KeyEquals(PCHAR Key, ULONG KeyLength, PCSTR Expected) {
    SIZE_T ExpectedLength = strlen(Expected);
    return KeyLength == ExpectedLength && RtlCompareMemory(Key, Expected, ExpectedLength) == ExpectedLength;
}

static RULE_CATEGORY ParseCategoryValue(PCHAR* Ptr, PCHAR End) {
    CHAR Value[24] = { 0 };
    if (!ParseStringValue(Ptr, End, Value, sizeof(Value))) return RuleCategoryUnknown;

    if (strcmp(Value, "Process") == 0) return RuleCategoryProcess;
    if (strcmp(Value, "File") == 0) return RuleCategoryFile;
    if (strcmp(Value, "Registry") == 0) return RuleCategoryRegistry;
    if (strcmp(Value, "Device") == 0) return RuleCategoryDevice;
    if (strcmp(Value, "Memory") == 0) return RuleCategoryMemory;
    if (strcmp(Value, "Thread") == 0) return RuleCategoryThread;
    return RuleCategoryUnknown;
}

static BOOLEAN IsValidDynamicRule(PDYNAMIC_RULE Rule) {
    if (!Rule || Rule->Invalid) return FALSE;
    if (Rule->Code == 0 || Rule->Category == RuleCategoryUnknown || Rule->Operations == 0) return FALSE;

    ULONG AllowedOperations = 0;

    if (Rule->Category == RuleCategoryProcess) {
        AllowedOperations =
            OP_EXECUTE |
            OP_TERMINATE |
            OP_SUSPEND_RESUME |
            OP_DUP_HANDLE |
            OP_SET_INFORMATION |
            OP_THREAD_SET_TOKEN |
            OP_CREATE_PROCESS |
            OP_IMAGE_LOAD |
            OP_IMPERSONATE;
    }
    else if (Rule->Category == RuleCategoryMemory) {
        AllowedOperations =
            OP_VM_READ |
            OP_VM_WRITE |
            OP_VM_OPERATION |
            OP_CREATE_THREAD |
            OP_THREAD_SET_CONTEXT;
    }
    else if (Rule->Category == RuleCategoryThread) {
        AllowedOperations = OP_EXECUTE;
    }
    else if (Rule->Category == RuleCategoryFile) {
        AllowedOperations = OP_WRITE | OP_DELETE | OP_CREATE | OP_EXECUTE | OP_RENAME;
    }
    else if (Rule->Category == RuleCategoryRegistry) {
        AllowedOperations = OP_WRITE | OP_DELETE | OP_CREATE;
    }
    else if (Rule->Category == RuleCategoryDevice) {
        AllowedOperations = OP_IOCTL;
    }

    if ((Rule->Operations & ~AllowedOperations) != 0) return FALSE;
    if (Rule->Threshold > 0 && Rule->TimeWindow == 0) Rule->TimeWindow = 1000;
    if (Rule->MaximumRiskScore > 0 && Rule->MaximumRiskScore < Rule->MinimumRiskScore) return FALSE;
    if (Rule->MaximumRegionSize > 0 && Rule->MaximumRegionSize < Rule->MinimumRegionSize) return FALSE;
    return TRUE;
}

static VOID ParseDynamicRules(PCHAR JsonContent, ULONG ContentLength) {
    if (!JsonContent || ContentLength == 0) return;

    PCHAR Ptr = JsonContent;
    PCHAR End = JsonContent + ContentLength;
    const CHAR DynamicRulesKey[] = "\"DynamicRules\"";
    SIZE_T DynamicRulesKeyLength = sizeof(DynamicRulesKey) - 1;

    while (Ptr + DynamicRulesKeyLength <= End) {
        if (RtlCompareMemory(Ptr, DynamicRulesKey, DynamicRulesKeyLength) != DynamicRulesKeyLength) {
            Ptr++;
            continue;
        }

        Ptr += DynamicRulesKeyLength;
        SkipWhitespace(&Ptr, End);
        if (Ptr >= End || *Ptr != ':') return;
        Ptr++;
        SkipWhitespace(&Ptr, End);
        if (Ptr >= End || *Ptr != '[') return;
        Ptr++;

        while (Ptr < End) {
            SkipWhitespace(&Ptr, End);
            if (Ptr >= End || *Ptr == ']') return;

            if (*Ptr != '{') {
                Ptr++;
                continue;
            }

            Ptr++;
            PDYNAMIC_RULE Rule = (PDYNAMIC_RULE)PyasAllocate(sizeof(DYNAMIC_RULE));
            if (!Rule) {
                SkipJsonValue(&Ptr, End);
                continue;
            }

            RtlZeroMemory(Rule, sizeof(*Rule));
            Rule->Category = RuleCategoryUnknown;
            Rule->OperationMatch = RuleOperationAny;

            while (Ptr < End) {
                SkipWhitespace(&Ptr, End);

                if (Ptr >= End) break;
                if (*Ptr == '}') {
                    Ptr++;
                    break;
                }

                if (*Ptr != '"') {
                    Ptr++;
                    continue;
                }

                PCHAR KeyStart = ++Ptr;
                while (Ptr < End && *Ptr != '"') Ptr++;
                if (Ptr >= End) break;

                ULONG KeyLength = (ULONG)(Ptr - KeyStart);
                Ptr++;
                SkipWhitespace(&Ptr, End);

                if (Ptr >= End || *Ptr != ':') {
                    SkipJsonValue(&Ptr, End);
                    continue;
                }

                Ptr++;
                SkipWhitespace(&Ptr, End);

                if (KeyEquals(KeyStart, KeyLength, "Code")) Rule->Code = ParseInt(&Ptr, End);
                else if (KeyEquals(KeyStart, KeyLength, "Kill")) {
                    if (!ParseBoolean(&Ptr, End, &Rule->Kill)) Rule->Invalid = TRUE;
                }
                else if (KeyEquals(KeyStart, KeyLength, "Priority")) Rule->Priority = ParseInt(&Ptr, End);
                else if (KeyEquals(KeyStart, KeyLength, "Threshold")) Rule->Threshold = ParseInt(&Ptr, End);
                else if (KeyEquals(KeyStart, KeyLength, "TimeWindow")) Rule->TimeWindow = ParseInt(&Ptr, End);
                else if (KeyEquals(KeyStart, KeyLength, "MinimumRiskScore")) Rule->MinimumRiskScore = ParseInt(&Ptr, End);
                else if (KeyEquals(KeyStart, KeyLength, "MaximumRiskScore")) Rule->MaximumRiskScore = ParseInt(&Ptr, End);
                else if (KeyEquals(KeyStart, KeyLength, "MinimumRegionSize")) Rule->MinimumRegionSize = ParseUnsigned64(&Ptr, End);
                else if (KeyEquals(KeyStart, KeyLength, "MaximumRegionSize")) Rule->MaximumRegionSize = ParseUnsigned64(&Ptr, End);
                else if (KeyEquals(KeyStart, KeyLength, "Category")) Rule->Category = ParseCategoryValue(&Ptr, End);
                else if (KeyEquals(KeyStart, KeyLength, "OperationMatch")) {
                    BOOLEAN Parsed = FALSE;
                    Rule->OperationMatch = ParseOperationMatch(&Ptr, End, &Parsed);
                    if (!Parsed) Rule->Invalid = TRUE;
                }
                else if (KeyEquals(KeyStart, KeyLength, "ParentMismatch")) {
                    BOOLEAN Parsed = FALSE;
                    Rule->ParentMismatch = ParseTriState(&Ptr, End, &Parsed);
                    if (!Parsed) Rule->Invalid = TRUE;
                }
                else if (KeyEquals(KeyStart, KeyLength, "FileOpenNameAvailable")) {
                    BOOLEAN Parsed = FALSE;
                    Rule->FileOpenNameAvailable = ParseTriState(&Ptr, End, &Parsed);
                    if (!Parsed) Rule->Invalid = TRUE;
                }
                else if (KeyEquals(KeyStart, KeyLength, "SubsystemProcess")) {
                    BOOLEAN Parsed = FALSE;
                    Rule->SubsystemProcess = ParseTriState(&Ptr, End, &Parsed);
                    if (!Parsed) Rule->Invalid = TRUE;
                }
                else if (KeyEquals(KeyStart, KeyLength, "Initiator")) ParseStringArray(&Ptr, End, &Rule->Initiator);
                else if (KeyEquals(KeyStart, KeyLength, "InitiatorExclude")) ParseStringArray(&Ptr, End, &Rule->InitiatorExclude);
                else if (KeyEquals(KeyStart, KeyLength, "InitiatorParent")) ParseStringArray(&Ptr, End, &Rule->InitiatorParent);
                else if (KeyEquals(KeyStart, KeyLength, "InitiatorParentExclude")) ParseStringArray(&Ptr, End, &Rule->InitiatorParentExclude);
                else if (KeyEquals(KeyStart, KeyLength, "InitiatorProcessTree")) ParseStringArray(&Ptr, End, &Rule->InitiatorProcessTree);
                else if (KeyEquals(KeyStart, KeyLength, "InitiatorProcessTreeExclude")) ParseStringArray(&Ptr, End, &Rule->InitiatorProcessTreeExclude);
                else if (KeyEquals(KeyStart, KeyLength, "Target")) ParseStringArray(&Ptr, End, &Rule->Target);
                else if (KeyEquals(KeyStart, KeyLength, "TargetExclude")) ParseStringArray(&Ptr, End, &Rule->TargetExclude);
                else if (KeyEquals(KeyStart, KeyLength, "TargetProcessTree")) ParseStringArray(&Ptr, End, &Rule->TargetProcessTree);
                else if (KeyEquals(KeyStart, KeyLength, "TargetProcessTreeExclude")) ParseStringArray(&Ptr, End, &Rule->TargetProcessTreeExclude);
                else if (KeyEquals(KeyStart, KeyLength, "Creator")) ParseStringArray(&Ptr, End, &Rule->Creator);
                else if (KeyEquals(KeyStart, KeyLength, "CreatorExclude")) ParseStringArray(&Ptr, End, &Rule->CreatorExclude);
                else if (KeyEquals(KeyStart, KeyLength, "Parent")) ParseStringArray(&Ptr, End, &Rule->Parent);
                else if (KeyEquals(KeyStart, KeyLength, "ParentExclude")) ParseStringArray(&Ptr, End, &Rule->ParentExclude);
                else if (KeyEquals(KeyStart, KeyLength, "CommandLine")) ParseStringArray(&Ptr, End, &Rule->CommandLine);
                else if (KeyEquals(KeyStart, KeyLength, "CommandLineExclude")) ParseStringArray(&Ptr, End, &Rule->CommandLineExclude);
                else if (KeyEquals(KeyStart, KeyLength, "Extensions")) ParseStringArray(&Ptr, End, &Rule->Extensions);
                else if (KeyEquals(KeyStart, KeyLength, "Operations")) {
                    if (!ParseOperationsArray(&Ptr, End, &Rule->Operations)) Rule->Invalid = TRUE;
                }
                else if (KeyEquals(KeyStart, KeyLength, "HandleTypes")) {
                    if (!ParseHandleTypesArray(&Ptr, End, &Rule->HandleTypes)) Rule->Invalid = TRUE;
                }
                else if (KeyEquals(KeyStart, KeyLength, "ObjectTypes")) {
                    if (!ParseObjectTypesArray(&Ptr, End, &Rule->ObjectTypes)) Rule->Invalid = TRUE;
                }
                else if (KeyEquals(KeyStart, KeyLength, "ThreadMemoryTypes")) {
                    if (!ParseThreadMemoryTypesArray(&Ptr, End, &Rule->ThreadMemoryTypes)) Rule->Invalid = TRUE;
                }
                else if (KeyEquals(KeyStart, KeyLength, "ThreadMemoryProtections")) {
                    if (!ParseThreadMemoryProtectionsArray(&Ptr, End, &Rule->ThreadMemoryProtections)) Rule->Invalid = TRUE;
                }
                else SkipJsonValue(&Ptr, End);
            }

            if (IsValidDynamicRule(Rule)) {
                Rule->Next = g_DynamicRules;
                g_DynamicRules = Rule;
            }
            else {
                FreeDynamicRule(Rule);
            }
        }

        return;
    }
}

NTSTATUS InitializeRulesEngine() {
    if (g_CacheInitialized) return STATUS_SUCCESS;

    NTSTATUS Status = ExInitializeResourceLite(&RuleLock);
    if (!NT_SUCCESS(Status)) return Status;

    KeInitializeSpinLock(&TrustCacheLock);
    InitializeListHead(&g_TerminationQueue);
    KeInitializeSpinLock(&g_TerminationLock);
    KeInitializeSemaphore(&g_TerminationSemaphore, 0, MAXLONG);
    InterlockedExchange(&g_PendingTerminations, 0);
    InterlockedExchange(&g_TerminationStopping, 0);

    Status = StartRuleTerminationWorker();
    if (!NT_SUCCESS(Status)) {
        InterlockedExchange(&g_TerminationStopping, 1);
        ExDeleteResourceLite(&RuleLock);
        return Status;
    }

    RtlZeroMemory(TrustCache, sizeof(TrustCache));
    RtlZeroMemory(BehaviorTrackers, sizeof(BehaviorTrackers));
    g_CacheInitialized = TRUE;
    return STATUS_SUCCESS;
}

VOID UninitializeRulesEngine() {
    if (!g_CacheInitialized) return;

    InterlockedExchange(&g_TerminationStopping, 1);
    StopRuleTerminationWorker();
    g_CacheInitialized = FALSE;
    ExDeleteResourceLite(&RuleLock);
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

        if (NT_SUCCESS(status) && FileInfo.EndOfFile.HighPart != 0) {
            status = STATUS_FILE_TOO_LARGE;
        }
        else if (NT_SUCCESS(status) && FileInfo.EndOfFile.LowPart > MAX_RULE_FILE_SIZE) {
            status = STATUS_FILE_TOO_LARGE;
        }
        else if (NT_SUCCESS(status) && FileInfo.EndOfFile.LowPart == 0) {
            status = STATUS_END_OF_FILE;
        }
        else if (NT_SUCCESS(status)) {
            ULONG FileSize = FileInfo.EndOfFile.LowPart;
            PVOID FileBuffer = PyasAllocate((SIZE_T)FileSize + 1);
            if (!FileBuffer) {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            else {
                status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatus, FileBuffer, FileSize, NULL, NULL);
                if (NT_SUCCESS(status) && IoStatus.Information != FileSize) {
                    status = STATUS_END_OF_FILE;
                }

                if (NT_SUCCESS(status)) {
                    ((PCHAR)FileBuffer)[FileSize] = '\0';
                    KeEnterCriticalRegion();
                    ExAcquireResourceExclusiveLite(&RuleLock, TRUE);
                    PDYNAMIC_RULE PreviousHead = g_DynamicRules;
                    ParseDynamicRules((PCHAR)FileBuffer, FileSize);
                    if (g_DynamicRules == PreviousHead) status = STATUS_DATA_ERROR;
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

        if (NT_SUCCESS(status) && FileInfo.EndOfFile.HighPart != 0) {
            status = STATUS_FILE_TOO_LARGE;
        }
        else if (NT_SUCCESS(status) && FileInfo.EndOfFile.LowPart > MAX_RULE_FILE_SIZE) {
            status = STATUS_FILE_TOO_LARGE;
        }
        else if (NT_SUCCESS(status) && FileInfo.EndOfFile.LowPart == 0) {
            status = STATUS_END_OF_FILE;
        }
        else if (NT_SUCCESS(status)) {
            ULONG FileSize = FileInfo.EndOfFile.LowPart;
            PVOID FileBuffer = PyasAllocate((SIZE_T)FileSize + 1);
            if (!FileBuffer) {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            else {
                status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatus, FileBuffer, FileSize, NULL, NULL);
                if (NT_SUCCESS(status) && IoStatus.Information != FileSize) {
                    status = STATUS_END_OF_FILE;
                }

                if (NT_SUCCESS(status)) {
                    ((PCHAR)FileBuffer)[FileSize] = '\0';
                    KeEnterCriticalRegion();
                    ExAcquireResourceExclusiveLite(&RuleLock, TRUE);
                    PDYNAMIC_RULE PreviousHead = g_DynamicRules;
                    ParseDynamicRules((PCHAR)FileBuffer, FileSize);
                    if (g_DynamicRules == PreviousHead) status = STATUS_DATA_ERROR;
                    ExReleaseResourceLite(&RuleLock);
                    KeLeaveCriticalRegion();
                }
                PyasFree(FileBuffer);
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
        FreeDynamicRule(CurrentRule);
        CurrentRule = Next;
    }
    g_DynamicRules = NULL;

    KIRQL OldIrql;
    KeAcquireSpinLock(&GlobalData.TrackerMutex, &OldIrql);
    RtlZeroMemory(BehaviorTrackers, sizeof(BehaviorTrackers));
    KeReleaseSpinLock(&GlobalData.TrackerMutex, OldIrql);

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
    if (ProcessId == (HANDLE)4) return TRUE;

    PEPROCESS Process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) return FALSE;

    BOOLEAN IsConnectedClient = FALSE;
    KIRQL PortIrql;
    KeAcquireSpinLock(&GlobalData.PortMutex, &PortIrql);
    IsConnectedClient = GlobalData.PyasProcess == Process;
    KeReleaseSpinLock(&GlobalData.PortMutex, PortIrql);

    if (IsConnectedClient) {
        ObDereferenceObject(Process);
        return TRUE;
    }

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
    NTSTATUS status = SeLocateProcessImageName(Process, &imageFileName);
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

static BOOLEAN TriStateMatches(RULE_TRI_STATE Condition, BOOLEAN Value) {
    if (Condition == RuleTriAny) return TRUE;
    if (Condition == RuleTriTrue) return Value ? TRUE : FALSE;
    return Value ? FALSE : TRUE;
}

static BOOLEAN RiskScoreMatches(PDYNAMIC_RULE Rule, ULONG RiskScore) {
    if (Rule->MinimumRiskScore > 0 && RiskScore < Rule->MinimumRiskScore) return FALSE;
    if (Rule->MaximumRiskScore > 0 && RiskScore > Rule->MaximumRiskScore) return FALSE;
    return TRUE;
}

static BOOLEAN GetProcessPath(HANDLE ProcessId, PUNICODE_STRING* Path) {
    if (Path) *Path = NULL;
    if (!Path || !ProcessId || KeGetCurrentIrql() != PASSIVE_LEVEL) return FALSE;
    return NT_SUCCESS(GetProcessImageName(ProcessId, Path)) && *Path && (*Path)->Buffer;
}

static BOOLEAN MatchDirectParent(
    HANDLE ProcessId,
    PRULE_NODE Include,
    PRULE_NODE Exclude
) {
    if (!Include && !Exclude) return TRUE;

    HANDLE ParentProcessId = NULL;
    if (!GetProcessRelation(ProcessId, &ParentProcessId, NULL) || !ParentProcessId) return FALSE;

    PUNICODE_STRING ParentPath = NULL;
    if (!GetProcessPath(ParentProcessId, &ParentPath)) return FALSE;

    BOOLEAN Match = EvaluateNodeConflict(Include, Exclude, ParentPath);
    ExFreePool(ParentPath);
    return Match;
}

static BOOLEAN MatchProcessTree(
    HANDLE ProcessId,
    PRULE_NODE Include,
    PRULE_NODE Exclude
) {
    if (!Include && !Exclude) return TRUE;
    if (!ProcessId) return FALSE;

    HANDLE CurrentProcessId = ProcessId;
    HANDLE Visited[12] = { 0 };
    ULONG VisitedCount = 0;
    BOOLEAN IncludeMatched = Include ? FALSE : TRUE;

    for (ULONG Depth = 0; Depth < RTL_NUMBER_OF(Visited); Depth++) {
        BOOLEAN Seen = FALSE;
        for (ULONG Index = 0; Index < VisitedCount; Index++) {
            if (Visited[Index] == CurrentProcessId) {
                Seen = TRUE;
                break;
            }
        }
        if (Seen) break;

        Visited[VisitedCount++] = CurrentProcessId;

        PUNICODE_STRING CurrentPath = NULL;
        if (GetProcessPath(CurrentProcessId, &CurrentPath)) {
            if (Exclude && MatchNodeListAny(Exclude, CurrentPath)) {
                ExFreePool(CurrentPath);
                return FALSE;
            }

            if (Include && MatchNodeListAny(Include, CurrentPath)) {
                IncludeMatched = TRUE;
            }

            ExFreePool(CurrentPath);
        }

        HANDLE ParentProcessId = NULL;
        if (!GetProcessRelation(CurrentProcessId, &ParentProcessId, NULL)) break;
        if (!ParentProcessId || ParentProcessId == CurrentProcessId) break;
        CurrentProcessId = ParentProcessId;
    }

    return IncludeMatched;
}

static ULONG CalculateAccessRisk(ULONG Operations, ULONG HandleType, ULONG ObjectType) {
    ULONG Score = 0;

    if (Operations & OP_VM_READ) Score += 10;
    if (Operations & OP_VM_WRITE) Score += 35;
    if (Operations & OP_VM_OPERATION) Score += 20;
    if (Operations & OP_CREATE_THREAD) Score += 45;
    if (Operations & OP_THREAD_SET_CONTEXT) Score += 50;
    if (Operations & OP_THREAD_SET_TOKEN) Score += 55;
    if (Operations & OP_TERMINATE) Score += 40;
    if (Operations & OP_SUSPEND_RESUME) Score += 25;
    if (Operations & OP_DUP_HANDLE) Score += 25;
    if (Operations & OP_SET_INFORMATION) Score += 20;
    if (Operations & OP_CREATE_PROCESS) Score += 35;
    if (Operations & OP_IMPERSONATE) Score += 55;
    if (HandleType == PYAS_HANDLE_DUPLICATE) Score += 10;
    if (ObjectType == PYAS_OBJECT_THREAD && (Operations & (OP_THREAD_SET_CONTEXT | OP_THREAD_SET_TOKEN | OP_IMPERSONATE))) {
        Score += 10;
    }

    return Score > 100 ? 100 : Score;
}

static ULONG CalculateThreadRisk(ULONG MemoryType, ULONG MemoryProtection, SIZE_T RegionSize) {
    ULONG Score = 20;

    if (MemoryType & PYAS_MEMORY_PRIVATE) Score += 40;
    else if (MemoryType & PYAS_MEMORY_MAPPED) Score += 20;
    else if (MemoryType & PYAS_MEMORY_IMAGE) Score += 5;

    if (MemoryProtection & PYAS_PROTECT_EXECUTE_WRITE) Score += 30;
    else if (MemoryProtection & PYAS_PROTECT_EXECUTE) Score += 10;

    if (RegionSize > 0 && RegionSize <= 1024 * 1024) Score += 5;
    return Score > 100 ? 100 : Score;
}

static ULONG CalculateProcessCreateRisk(HANDLE CreatorPid, HANDLE ParentPid, BOOLEAN IsSubsystemProcess) {
    ULONG Score = 0;
    if (CreatorPid && ParentPid && CreatorPid != ParentPid) Score += 35;
    if (IsSubsystemProcess) Score += 10;
    return Score;
}

static ULONG GetMatchedOperations(PDYNAMIC_RULE Rule, ULONG RequestedOperations) {
    ULONG RuleOperations = Rule->Operations & RequestedOperations;
    if (RuleOperations == 0) return 0;

    if (Rule->OperationMatch == RuleOperationAll) {
        ULONG RelevantOperations = Rule->Operations & (
            OP_VM_READ |
            OP_VM_WRITE |
            OP_VM_OPERATION |
            OP_CREATE_THREAD |
            OP_THREAD_SET_CONTEXT |
            OP_THREAD_SET_TOKEN |
            OP_TERMINATE |
            OP_SUSPEND_RESUME |
            OP_DUP_HANDLE |
            OP_SET_INFORMATION |
            OP_CREATE_PROCESS |
            OP_IMPERSONATE
            );

        if (RelevantOperations == 0 || (RequestedOperations & RelevantOperations) != RelevantOperations) {
            return 0;
        }

        return RelevantOperations;
    }

    return RuleOperations;
}

static BOOLEAN MatchSourceTargetRule(
    PDYNAMIC_RULE Rule,
    HANDLE SourcePid,
    HANDLE TargetPid,
    PCUNICODE_STRING SourcePath,
    PCUNICODE_STRING TargetPath,
    ULONG HandleType,
    ULONG ObjectType,
    ULONG RiskScore
) {
    if (Rule->HandleTypes != 0 && (Rule->HandleTypes & HandleType) == 0) return FALSE;
    if (Rule->ObjectTypes != 0 && (Rule->ObjectTypes & ObjectType) == 0) return FALSE;
    if (!RiskScoreMatches(Rule, RiskScore)) return FALSE;
    if (!EvaluateNodeConflict(Rule->Initiator, Rule->InitiatorExclude, SourcePath)) return FALSE;
    if (!EvaluateNodeConflict(Rule->Target, Rule->TargetExclude, TargetPath)) return FALSE;
    if (!MatchDirectParent(SourcePid, Rule->InitiatorParent, Rule->InitiatorParentExclude)) return FALSE;
    if (!MatchProcessTree(SourcePid, Rule->InitiatorProcessTree, Rule->InitiatorProcessTreeExclude)) return FALSE;
    if (!MatchProcessTree(TargetPid, Rule->TargetProcessTree, Rule->TargetProcessTreeExclude)) return FALSE;
    return TRUE;
}

BOOLEAN EvaluateProcessCreateRule(
    HANDLE CreatorPid,
    HANDLE ParentPid,
    HANDLE ProcessId,
    PCUNICODE_STRING TargetPath,
    PCUNICODE_STRING CommandLine,
    BOOLEAN FileOpenNameAvailable,
    BOOLEAN IsSubsystemProcess,
    PULONG OutCode,
    PBOOLEAN OutKill
) {
    UNREFERENCED_PARAMETER(ProcessId);

    if (!OutCode || !OutKill || !CreatorPid) return FALSE;
    *OutCode = 0;
    *OutKill = FALSE;
    if (IsProcessTrusted(CreatorPid)) return FALSE;

    PUNICODE_STRING CreatorPath = NULL;
    PUNICODE_STRING ParentPath = NULL;
    GetProcessPath(CreatorPid, &CreatorPath);
    if (ParentPid) GetProcessPath(ParentPid, &ParentPath);

    BOOLEAN ParentMismatch = CreatorPid && ParentPid && CreatorPid != ParentPid;
    ULONG RiskScore = CalculateProcessCreateRisk(CreatorPid, ParentPid, IsSubsystemProcess);
    BOOLEAN Blocked = FALSE;
    ULONG SelectedPriority = 0;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&RuleLock, TRUE);

    for (PDYNAMIC_RULE Rule = g_DynamicRules; Rule; Rule = Rule->Next) {
        if (Rule->Category != RuleCategoryProcess || (Rule->Operations & OP_EXECUTE) == 0) continue;
        if (!TriStateMatches(Rule->ParentMismatch, ParentMismatch)) continue;
        if (!TriStateMatches(Rule->FileOpenNameAvailable, FileOpenNameAvailable)) continue;
        if (!TriStateMatches(Rule->SubsystemProcess, IsSubsystemProcess)) continue;
        if (!RiskScoreMatches(Rule, RiskScore)) continue;
        if (!EvaluateNodeConflict(Rule->Initiator, Rule->InitiatorExclude, CreatorPath)) continue;
        if (!EvaluateNodeConflict(Rule->Creator, Rule->CreatorExclude, CreatorPath)) continue;
        if (!EvaluateNodeConflict(Rule->Parent, Rule->ParentExclude, ParentPath)) continue;
        if (!EvaluateNodeConflict(Rule->Target, Rule->TargetExclude, TargetPath)) continue;
        if (!MatchDirectParent(CreatorPid, Rule->InitiatorParent, Rule->InitiatorParentExclude)) continue;
        if (!MatchProcessTree(CreatorPid, Rule->InitiatorProcessTree, Rule->InitiatorProcessTreeExclude)) continue;
        if (!MatchProcessTree(ParentPid, Rule->TargetProcessTree, Rule->TargetProcessTreeExclude)) continue;
        if (Rule->CommandLine && !MatchNodeListAny(Rule->CommandLine, CommandLine)) continue;
        if (Rule->CommandLineExclude && MatchNodeListAny(Rule->CommandLineExclude, CommandLine)) continue;
        if (!CheckRuleThreshold(Rule, CreatorPid)) continue;

        if (!Blocked || Rule->Priority >= SelectedPriority) {
            *OutCode = Rule->Code;
            *OutKill = Rule->Kill;
            SelectedPriority = Rule->Priority;
        }
        Blocked = TRUE;
    }

    ExReleaseResourceLite(&RuleLock);
    KeLeaveCriticalRegion();

    if (CreatorPath) ExFreePool(CreatorPath);
    if (ParentPath) ExFreePool(ParentPath);
    return Blocked;
}

BOOLEAN EvaluateProcessAccessRule(
    HANDLE SourcePid,
    HANDLE TargetPid,
    ULONG RequestedOperations,
    ULONG HandleType,
    ULONG ObjectType,
    PULONG DeniedOperations,
    PULONG OutCode,
    PBOOLEAN OutKill
) {
    if (!DeniedOperations || !OutCode || !OutKill || !SourcePid || !TargetPid || RequestedOperations == 0) return FALSE;

    *DeniedOperations = 0;
    *OutCode = 0;
    *OutKill = FALSE;
    if (IsProcessTrusted(SourcePid)) return FALSE;

    PUNICODE_STRING SourcePath = NULL;
    PUNICODE_STRING TargetPath = NULL;
    GetProcessPath(SourcePid, &SourcePath);
    GetProcessPath(TargetPid, &TargetPath);

    ULONG RiskScore = CalculateAccessRisk(RequestedOperations, HandleType, ObjectType);
    ULONG SelectedPriority = 0;
    BOOLEAN Matched = FALSE;

    const ULONG MemoryOperations =
        OP_VM_READ |
        OP_VM_WRITE |
        OP_VM_OPERATION |
        OP_CREATE_THREAD |
        OP_THREAD_SET_CONTEXT;

    const ULONG ControlOperations =
        OP_THREAD_SET_TOKEN |
        OP_TERMINATE |
        OP_SUSPEND_RESUME |
        OP_DUP_HANDLE |
        OP_SET_INFORMATION |
        OP_CREATE_PROCESS |
        OP_IMPERSONATE;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&RuleLock, TRUE);

    for (PDYNAMIC_RULE Rule = g_DynamicRules; Rule; Rule = Rule->Next) {
        ULONG CategoryOperations = 0;

        if (Rule->Category == RuleCategoryMemory) {
            CategoryOperations = RequestedOperations & MemoryOperations;
        }
        else if (Rule->Category == RuleCategoryProcess) {
            CategoryOperations = RequestedOperations & ControlOperations;
        }
        else {
            continue;
        }

        if (CategoryOperations == 0) continue;

        ULONG RuleMatchedOperations = GetMatchedOperations(Rule, CategoryOperations);
        if (RuleMatchedOperations == 0) continue;
        if (!MatchSourceTargetRule(
            Rule,
            SourcePid,
            TargetPid,
            SourcePath,
            TargetPath,
            HandleType,
            ObjectType,
            RiskScore
        )) continue;
        if (!CheckRuleThreshold(Rule, SourcePid)) continue;

        *DeniedOperations |= RuleMatchedOperations;

        if (!Matched || Rule->Priority >= SelectedPriority) {
            *OutCode = Rule->Code;
            *OutKill = Rule->Kill;
            SelectedPriority = Rule->Priority;
        }
        Matched = TRUE;
    }

    ExReleaseResourceLite(&RuleLock);
    KeLeaveCriticalRegion();

    if (SourcePath) ExFreePool(SourcePath);
    if (TargetPath) ExFreePool(TargetPath);
    return Matched && *DeniedOperations != 0;
}

BOOLEAN EvaluateThreadRule(
    HANDLE SourcePid,
    HANDLE TargetPid,
    PVOID StartAddress,
    ULONG MemoryType,
    ULONG MemoryProtection,
    SIZE_T RegionSize,
    PULONG OutCode,
    PBOOLEAN OutKill
) {
    UNREFERENCED_PARAMETER(StartAddress);

    if (!OutCode || !OutKill || !SourcePid || !TargetPid) return FALSE;
    *OutCode = 0;
    *OutKill = FALSE;
    if (IsProcessTrusted(SourcePid)) return FALSE;

    PUNICODE_STRING SourcePath = NULL;
    PUNICODE_STRING TargetPath = NULL;
    GetProcessPath(SourcePid, &SourcePath);
    GetProcessPath(TargetPid, &TargetPath);

    ULONG RiskScore = CalculateThreadRisk(MemoryType, MemoryProtection, RegionSize);
    ULONG SelectedPriority = 0;
    BOOLEAN Matched = FALSE;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&RuleLock, TRUE);

    for (PDYNAMIC_RULE Rule = g_DynamicRules; Rule; Rule = Rule->Next) {
        if (Rule->Category != RuleCategoryThread || (Rule->Operations & OP_EXECUTE) == 0) continue;

        ULONG RequiredMemoryTypes = Rule->ThreadMemoryTypes != 0
            ? Rule->ThreadMemoryTypes
            : PYAS_MEMORY_PRIVATE;
        ULONG RequiredProtections = Rule->ThreadMemoryProtections != 0
            ? Rule->ThreadMemoryProtections
            : PYAS_PROTECT_EXECUTE;

        if ((RequiredMemoryTypes & MemoryType) == 0) continue;
        if ((RequiredProtections & MemoryProtection) == 0) continue;
        if (Rule->MinimumRegionSize > 0 && RegionSize < Rule->MinimumRegionSize) continue;
        if (Rule->MaximumRegionSize > 0 && RegionSize > Rule->MaximumRegionSize) continue;
        if (!MatchSourceTargetRule(
            Rule,
            SourcePid,
            TargetPid,
            SourcePath,
            TargetPath,
            PYAS_HANDLE_CREATE,
            PYAS_OBJECT_THREAD,
            RiskScore
        )) continue;
        if (!CheckRuleThreshold(Rule, SourcePid)) continue;

        if (!Matched || Rule->Priority >= SelectedPriority) {
            *OutCode = Rule->Code;
            *OutKill = Rule->Kill;
            SelectedPriority = Rule->Priority;
        }
        Matched = TRUE;
    }

    ExReleaseResourceLite(&RuleLock);
    KeLeaveCriticalRegion();

    if (SourcePath) ExFreePool(SourcePath);
    if (TargetPath) ExFreePool(TargetPath);
    return Matched;
}

BOOLEAN EvaluateImageLoadRule(
    HANDLE ProcessId,
    PCUNICODE_STRING ImagePath,
    PIMAGE_INFO ImageInfo,
    PULONG OutCode,
    PBOOLEAN OutKill
) {
    if (!OutCode || !OutKill || !ProcessId || !ImagePath || !ImagePath->Buffer || !ImageInfo) return FALSE;
    *OutCode = 0;
    *OutKill = FALSE;

    PUNICODE_STRING ProcessPath = NULL;
    GetProcessPath(ProcessId, &ProcessPath);

    BOOLEAN Matched = FALSE;
    ULONG SelectedPriority = 0;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&RuleLock, TRUE);

    for (PDYNAMIC_RULE Rule = g_DynamicRules; Rule; Rule = Rule->Next) {
        if (Rule->Category != RuleCategoryProcess || (Rule->Operations & OP_IMAGE_LOAD) == 0) continue;
        if (!EvaluateNodeConflict(Rule->Initiator, Rule->InitiatorExclude, ProcessPath)) continue;
        if (!EvaluateNodeConflict(Rule->Target, Rule->TargetExclude, ImagePath)) continue;
        if (!MatchDirectParent(ProcessId, Rule->InitiatorParent, Rule->InitiatorParentExclude)) continue;
        if (!MatchProcessTree(ProcessId, Rule->InitiatorProcessTree, Rule->InitiatorProcessTreeExclude)) continue;
        if (!MatchProcessTree(ProcessId, Rule->TargetProcessTree, Rule->TargetProcessTreeExclude)) continue;
        if (Rule->MinimumRegionSize > 0 && ImageInfo->ImageSize < Rule->MinimumRegionSize) continue;
        if (Rule->MaximumRegionSize > 0 && ImageInfo->ImageSize > Rule->MaximumRegionSize) continue;
        if (!CheckRuleThreshold(Rule, ProcessId)) continue;

        if (!Matched || Rule->Priority >= SelectedPriority) {
            *OutCode = Rule->Code;
            *OutKill = Rule->Kill;
            SelectedPriority = Rule->Priority;
        }
        Matched = TRUE;
    }

    ExReleaseResourceLite(&RuleLock);
    KeLeaveCriticalRegion();

    if (ProcessPath) ExFreePool(ProcessPath);
    return Matched;
}

BOOLEAN EvaluateProcessRule(
    HANDLE ProcessId,
    PCUNICODE_STRING TargetPath,
    PCUNICODE_STRING CommandLine,
    PULONG OutCode,
    PBOOLEAN OutKill
) {
    return EvaluateProcessCreateRule(
        ProcessId,
        NULL,
        NULL,
        TargetPath,
        CommandLine,
        TRUE,
        FALSE,
        OutCode,
        OutKill
    );
}

BOOLEAN EvaluateFileRule(HANDLE ProcessId, PCUNICODE_STRING TargetPath, ULONG Operation, PVOID WriteBuffer, ULONG WriteLength, PULONG OutCode, PBOOLEAN OutKill) {
    UNREFERENCED_PARAMETER(WriteBuffer);
    UNREFERENCED_PARAMETER(WriteLength);

    if (!OutCode || !OutKill) return FALSE;
    *OutCode = 0;
    *OutKill = FALSE;
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
                *OutKill = Rule->Kill;
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

BOOLEAN EvaluateRegistryRule(HANDLE ProcessId, PCUNICODE_STRING KeyName, ULONG Operation, PULONG OutCode, PBOOLEAN OutKill) {
    if (!OutCode || !OutKill) return FALSE;
    *OutCode = 0;
    *OutKill = FALSE;
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
                *OutKill = Rule->Kill;
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

BOOLEAN EvaluateDeviceRule(HANDLE ProcessId, PULONG OutCode, PBOOLEAN OutKill) {
    if (!OutCode || !OutKill) return FALSE;
    *OutCode = 0;
    *OutKill = FALSE;
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
                *OutKill = Rule->Kill;
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

BOOLEAN EvaluateMemoryRule(HANDLE SourcePid, HANDLE TargetPid, ULONG Operation, PULONG OutCode, PBOOLEAN OutKill) {
    ULONG DeniedOperations = 0;
    return EvaluateProcessAccessRule(
        SourcePid,
        TargetPid,
        Operation,
        PYAS_HANDLE_CREATE,
        PYAS_OBJECT_PROCESS,
        &DeniedOperations,
        OutCode,
        OutKill
    );
}

BOOLEAN EvaluateProcessHandleRule(HANDLE SourcePid, HANDLE TargetPid, ULONG Operation, PULONG OutCode, PBOOLEAN OutKill) {
    ULONG DeniedOperations = 0;
    return EvaluateProcessAccessRule(
        SourcePid,
        TargetPid,
        Operation,
        PYAS_HANDLE_CREATE,
        PYAS_OBJECT_PROCESS,
        &DeniedOperations,
        OutCode,
        OutKill
    );
}

NTSTATUS SendMessageToUser(ULONG Code, ULONG Pid, PWCHAR Path, USHORT PathSize) {
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_UNSUCCESSFUL;

    LONG DriverState = InterlockedCompareExchange(
        &GlobalData.DriverState,
        PyasDriverStateCold,
        PyasDriverStateCold
    );

    if (DriverState != PyasDriverStateRunning && DriverState != PyasDriverStateStopRetry) {
        return STATUS_PORT_DISCONNECTED;
    }

    if (InterlockedCompareExchange(&GlobalData.PortStopping, 0, 0) != 0) return STATUS_PORT_DISCONNECTED;
    if (!ExAcquireRundownProtection(&GlobalData.PortRundown)) return STATUS_PORT_DISCONNECTED;

    NTSTATUS status = STATUS_PORT_DISCONNECTED;

    if (GlobalData.ClientPort) {
        PPYAS_MESSAGE msg = (PPYAS_MESSAGE)PyasAllocate(sizeof(PYAS_MESSAGE));
        if (msg) {
            RtlZeroMemory(msg, sizeof(*msg));
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