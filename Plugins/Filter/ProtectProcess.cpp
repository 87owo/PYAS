#include "DriverCommon.h"

constexpr auto PROCESS_RELATION_BUCKET_COUNT = 1024;
constexpr auto PROCESS_RELATION_BUCKET_WAYS = 4;

typedef HANDLE(NTAPI* PPS_GET_PROCESS_INHERITED_FROM_UNIQUE_PROCESS_ID)(PEPROCESS Process);

typedef struct _PROCESS_RELATION_ENTRY {
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    HANDLE CreatorProcessId;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ParentCreateTime;
    ULONGLONG Sequence;
} PROCESS_RELATION_ENTRY, * PPROCESS_RELATION_ENTRY;

static PROCESS_RELATION_ENTRY g_ProcessRelations[PROCESS_RELATION_BUCKET_COUNT][PROCESS_RELATION_BUCKET_WAYS];
static KSPIN_LOCK g_ProcessRelationLock;
static EX_RUNDOWN_REF g_ProcessRundown;
static volatile LONG g_ProcessStopping = 1;
static volatile LONG64 g_ProcessRelationSequence = 0;
static BOOLEAN g_ProcessProtectionInitialized = FALSE;
static PPS_GET_PROCESS_INHERITED_FROM_UNIQUE_PROCESS_ID g_GetInheritedProcessId = NULL;

static ULONG GetProcessRelationBucket(HANDLE ProcessId) {
    return ((ULONG)(ULONG_PTR)ProcessId >> 2) & (PROCESS_RELATION_BUCKET_COUNT - 1);
}

static BOOLEAN QueryProcessCreateTime(HANDLE ProcessId, PLARGE_INTEGER CreateTime) {
    if (CreateTime) CreateTime->QuadPart = 0;
    if (!ProcessId || !CreateTime || KeGetCurrentIrql() > APC_LEVEL) return FALSE;

    PEPROCESS Process = NULL;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) return FALSE;

    CreateTime->QuadPart = PsGetProcessCreateTimeQuadPart(Process);
    ObDereferenceObject(Process);
    return TRUE;
}

static VOID StoreProcessRelation(
    PEPROCESS Process,
    HANDLE ProcessId,
    HANDLE ParentProcessId,
    HANDLE CreatorProcessId,
    PLARGE_INTEGER KnownParentCreateTime
) {
    if (!Process || !ProcessId) return;

    PROCESS_RELATION_ENTRY NewEntry = { 0 };
    NewEntry.ProcessId = ProcessId;
    NewEntry.ParentProcessId = ParentProcessId;
    NewEntry.CreatorProcessId = CreatorProcessId;
    NewEntry.CreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);

    if (KnownParentCreateTime) {
        NewEntry.ParentCreateTime = *KnownParentCreateTime;
    }
    else if (ParentProcessId) {
        QueryProcessCreateTime(ParentProcessId, &NewEntry.ParentCreateTime);
    }

    NewEntry.Sequence = (ULONGLONG)InterlockedIncrement64(&g_ProcessRelationSequence);

    ULONG Bucket = GetProcessRelationBucket(ProcessId);
    ULONG Selected = 0;

    KIRQL OldIrql;
    KeAcquireSpinLock(&g_ProcessRelationLock, &OldIrql);

    for (ULONG Index = 0; Index < PROCESS_RELATION_BUCKET_WAYS; Index++) {
        PPROCESS_RELATION_ENTRY Entry = &g_ProcessRelations[Bucket][Index];

        if (Entry->ProcessId == ProcessId || Entry->ProcessId == NULL) {
            Selected = Index;
            break;
        }

        if (Entry->Sequence < g_ProcessRelations[Bucket][Selected].Sequence) {
            Selected = Index;
        }
    }

    g_ProcessRelations[Bucket][Selected] = NewEntry;
    KeReleaseSpinLock(&g_ProcessRelationLock, OldIrql);
}

static VOID RemoveProcessRelation(HANDLE ProcessId) {
    if (!ProcessId) return;

    ULONG Bucket = GetProcessRelationBucket(ProcessId);

    KIRQL OldIrql;
    KeAcquireSpinLock(&g_ProcessRelationLock, &OldIrql);

    for (ULONG Index = 0; Index < PROCESS_RELATION_BUCKET_WAYS; Index++) {
        PPROCESS_RELATION_ENTRY Entry = &g_ProcessRelations[Bucket][Index];
        if (Entry->ProcessId == ProcessId) {
            RtlZeroMemory(Entry, sizeof(*Entry));
            break;
        }
    }

    KeReleaseSpinLock(&g_ProcessRelationLock, OldIrql);
}

BOOLEAN GetProcessRelation(
    HANDLE ProcessId,
    PHANDLE ParentProcessId,
    PHANDLE CreatorProcessId
) {
    if (ParentProcessId) *ParentProcessId = NULL;
    if (CreatorProcessId) *CreatorProcessId = NULL;
    if (!ProcessId || !g_ProcessProtectionInitialized || KeGetCurrentIrql() > APC_LEVEL) return FALSE;

    PEPROCESS Process = NULL;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) return FALSE;

    LARGE_INTEGER CurrentCreateTime = { 0 };
    CurrentCreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);

    PROCESS_RELATION_ENTRY Snapshot = { 0 };
    ULONG Bucket = GetProcessRelationBucket(ProcessId);

    KIRQL OldIrql;
    KeAcquireSpinLock(&g_ProcessRelationLock, &OldIrql);

    for (ULONG Index = 0; Index < PROCESS_RELATION_BUCKET_WAYS; Index++) {
        PPROCESS_RELATION_ENTRY Entry = &g_ProcessRelations[Bucket][Index];
        if (Entry->ProcessId == ProcessId) {
            Snapshot = *Entry;
            break;
        }
    }

    KeReleaseSpinLock(&g_ProcessRelationLock, OldIrql);

    BOOLEAN CacheValid = Snapshot.ProcessId == ProcessId &&
        Snapshot.CreateTime.QuadPart == CurrentCreateTime.QuadPart;

    if (CacheValid && Snapshot.ParentProcessId && Snapshot.ParentCreateTime.QuadPart != 0) {
        LARGE_INTEGER LiveParentCreateTime = { 0 };
        if (QueryProcessCreateTime(Snapshot.ParentProcessId, &LiveParentCreateTime) &&
            LiveParentCreateTime.QuadPart != Snapshot.ParentCreateTime.QuadPart) {
            CacheValid = FALSE;
        }
    }

    if (CacheValid) {
        if (ParentProcessId) *ParentProcessId = Snapshot.ParentProcessId;
        if (CreatorProcessId) *CreatorProcessId = Snapshot.CreatorProcessId;
        ObDereferenceObject(Process);
        return Snapshot.ParentProcessId != NULL || Snapshot.CreatorProcessId != NULL;
    }

    if (Snapshot.ProcessId == ProcessId) {
        RemoveProcessRelation(ProcessId);
    }

    HANDLE LiveParentProcessId = NULL;
    LARGE_INTEGER LiveParentCreateTime = { 0 };

    if (g_GetInheritedProcessId) {
        LiveParentProcessId = g_GetInheritedProcessId(Process);
    }

    if (!LiveParentProcessId || LiveParentProcessId == ProcessId) {
        ObDereferenceObject(Process);
        return FALSE;
    }

    if (!QueryProcessCreateTime(LiveParentProcessId, &LiveParentCreateTime) ||
        LiveParentCreateTime.QuadPart > CurrentCreateTime.QuadPart) {
        ObDereferenceObject(Process);
        return FALSE;
    }

    StoreProcessRelation(
        Process,
        ProcessId,
        LiveParentProcessId,
        NULL,
        &LiveParentCreateTime
    );

    if (ParentProcessId) *ParentProcessId = LiveParentProcessId;
    if (CreatorProcessId) *CreatorProcessId = NULL;

    ObDereferenceObject(Process);
    return TRUE;
}

NTSTATUS InitializeProcessProtection() {
    if (g_ProcessProtectionInitialized) return STATUS_SUCCESS;

    KeInitializeSpinLock(&g_ProcessRelationLock);
    RtlZeroMemory(g_ProcessRelations, sizeof(g_ProcessRelations));
    InterlockedExchange64(&g_ProcessRelationSequence, 0);
    ExInitializeRundownProtection(&g_ProcessRundown);

    UNICODE_STRING RoutineName = RTL_CONSTANT_STRING(L"PsGetProcessInheritedFromUniqueProcessId");
    g_GetInheritedProcessId = reinterpret_cast<PPS_GET_PROCESS_INHERITED_FROM_UNIQUE_PROCESS_ID>(
        MmGetSystemRoutineAddress(&RoutineName)
        );

    InterlockedExchange(&g_ProcessStopping, 0);
    g_ProcessProtectionInitialized = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS UninitializeProcessProtection() {
    if (!g_ProcessProtectionInitialized) return STATUS_SUCCESS;

    InterlockedExchange(&g_ProcessStopping, 1);
    ExWaitForRundownProtectionRelease(&g_ProcessRundown);

    KIRQL OldIrql;
    KeAcquireSpinLock(&g_ProcessRelationLock, &OldIrql);
    RtlZeroMemory(g_ProcessRelations, sizeof(g_ProcessRelations));
    KeReleaseSpinLock(&g_ProcessRelationLock, OldIrql);

    g_GetInheritedProcessId = NULL;
    g_ProcessProtectionInitialized = FALSE;
    return STATUS_SUCCESS;
}

VOID ProcessNotifyCallbackEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    if (!g_ProcessProtectionInitialized) return;
    if (InterlockedCompareExchange(&g_ProcessStopping, 0, 0) != 0) return;
    if (!ExAcquireRundownProtection(&g_ProcessRundown)) return;

    if (!CreateInfo) {
        RemoveProcessRelation(ProcessId);
        ExReleaseRundownProtection(&g_ProcessRundown);
        return;
    }

    if (!NT_SUCCESS(CreateInfo->CreationStatus)) {
        ExReleaseRundownProtection(&g_ProcessRundown);
        return;
    }

    HANDLE CreatorPid = CreateInfo->CreatingThreadId.UniqueProcess;
    HANDLE ParentPid = CreateInfo->ParentProcessId;
    ULONG RuleCode = 0;
    BOOLEAN Kill = FALSE;

    BOOLEAN Blocked = EvaluateProcessCreateRule(
        CreatorPid,
        ParentPid,
        ProcessId,
        CreateInfo->ImageFileName,
        CreateInfo->CommandLine,
        CreateInfo->FileOpenNameAvailable ? TRUE : FALSE,
        CreateInfo->IsSubsystemProcess ? TRUE : FALSE,
        &RuleCode,
        &Kill
    );

    if (Blocked) {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;

        if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
            SendMessageToUser(
                RuleCode,
                (ULONG)(ULONG_PTR)CreatorPid,
                CreateInfo->ImageFileName->Buffer,
                CreateInfo->ImageFileName->Length
            );
        }

        QueueRuleProcessTermination(CreatorPid, Kill);
    }
    else {
        StoreProcessRelation(Process, ProcessId, ParentPid, CreatorPid, NULL);
    }

    ExReleaseRundownProtection(&g_ProcessRundown);
}
