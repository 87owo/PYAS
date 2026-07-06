#include "DriverCommon.h"

extern "C" {
    NTSTATUS ZwOpenThread(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );

    NTSTATUS ZwQueryInformationThread(
        HANDLE ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength,
        PULONG ReturnLength
    );
}

#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION 0x0040
#endif

#define THREAD_QUERY_SET_WIN32_START_ADDRESS 9

constexpr ULONG PYAS_MEM_IMAGE_TYPE = 0x01000000UL;

typedef enum _MEMORY_WORK_TYPE {
    MemoryWorkThreadAnalysis = 1,
    MemoryWorkViolationReport = 2
} MEMORY_WORK_TYPE;

typedef struct _MEMORY_WORK_ITEM {
    LIST_ENTRY Entry;
    MEMORY_WORK_TYPE Type;
    PEPROCESS SourceProcess;
    PEPROCESS TargetProcess;
    HANDLE SourcePid;
    HANDLE TargetPid;
    HANDLE ThreadId;
    ULONG RuleCode;
    BOOLEAN Kill;
    WCHAR FallbackMessage[64];
} MEMORY_WORK_ITEM, * PMEMORY_WORK_ITEM;

typedef struct _THREAD_MEMORY_REGION {
    PVOID StartAddress;
    ULONG MemoryType;
    ULONG MemoryProtection;
    SIZE_T RegionSize;
} THREAD_MEMORY_REGION, * PTHREAD_MEMORY_REGION;

static BOOLEAN g_ThreadNotifyRegistered = FALSE;
static BOOLEAN g_LoadImageNotifyRegistered = FALSE;
static BOOLEAN g_MemoryProtectionInitialized = FALSE;
static BOOLEAN g_MemoryRundownCompleted = FALSE;
static EX_RUNDOWN_REF g_MemoryRundown;
static volatile LONG g_MemoryStopping = 1;
static volatile LONG g_PendingMemoryWork = 0;
static LIST_ENTRY g_MemoryWorkQueue;
static KSPIN_LOCK g_MemoryWorkLock;
static KSEMAPHORE g_MemoryWorkSemaphore;
static HANDLE g_MemoryWorkerHandle = NULL;
constexpr auto MAX_PENDING_MEMORY_WORK = 256;
constexpr auto MEMORY_WORKER_STOP_TIMEOUT_MS = 2000;

static PACCESS_MASK GetDesiredAccessPointer(POB_PRE_OPERATION_INFORMATION OperationInformation) {
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        return &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    }

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        return &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    return NULL;
}

static ULONG GetHandleType(POB_PRE_OPERATION_INFORMATION OperationInformation) {
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        return PYAS_HANDLE_CREATE;
    }

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        return PYAS_HANDLE_DUPLICATE;
    }

    return 0;
}

static ULONG GetProcessOperations(ACCESS_MASK Access) {
    ULONG Operations = 0;

    if (Access & PROCESS_VM_READ) Operations |= OP_VM_READ;
    if (Access & PROCESS_VM_WRITE) Operations |= OP_VM_WRITE;
    if (Access & PROCESS_VM_OPERATION) Operations |= OP_VM_OPERATION;
    if (Access & PROCESS_CREATE_THREAD) Operations |= OP_CREATE_THREAD;
    if (Access & PROCESS_TERMINATE) Operations |= OP_TERMINATE;
    if (Access & PROCESS_SUSPEND_RESUME) Operations |= OP_SUSPEND_RESUME;
    if (Access & PROCESS_DUP_HANDLE) Operations |= OP_DUP_HANDLE;
    if (Access & (PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA)) Operations |= OP_SET_INFORMATION;
    if (Access & PROCESS_CREATE_PROCESS) Operations |= OP_CREATE_PROCESS;

    return Operations;
}

static ULONG GetThreadOperations(ACCESS_MASK Access) {
    ULONG Operations = 0;

    if (Access & THREAD_SET_CONTEXT) Operations |= OP_THREAD_SET_CONTEXT;
    if (Access & THREAD_TERMINATE) Operations |= OP_TERMINATE;
    if (Access & THREAD_SUSPEND_RESUME) Operations |= OP_SUSPEND_RESUME;
    if (Access & THREAD_SET_INFORMATION) Operations |= OP_SET_INFORMATION;
    if (Access & THREAD_SET_THREAD_TOKEN) Operations |= OP_THREAD_SET_TOKEN;
    if (Access & (THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION)) Operations |= OP_IMPERSONATE;

    return Operations;
}

static ACCESS_MASK GetProcessDeniedAccess(ULONG Operations) {
    ACCESS_MASK DeniedAccess = 0;

    if (Operations & OP_VM_READ) DeniedAccess |= PROCESS_VM_READ;
    if (Operations & OP_VM_WRITE) DeniedAccess |= PROCESS_VM_WRITE;
    if (Operations & OP_VM_OPERATION) DeniedAccess |= PROCESS_VM_OPERATION;
    if (Operations & OP_CREATE_THREAD) DeniedAccess |= PROCESS_CREATE_THREAD;
    if (Operations & OP_TERMINATE) DeniedAccess |= PROCESS_TERMINATE;
    if (Operations & OP_SUSPEND_RESUME) DeniedAccess |= PROCESS_SUSPEND_RESUME;
    if (Operations & OP_DUP_HANDLE) DeniedAccess |= PROCESS_DUP_HANDLE;
    if (Operations & OP_SET_INFORMATION) DeniedAccess |= PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA;
    if (Operations & OP_CREATE_PROCESS) DeniedAccess |= PROCESS_CREATE_PROCESS;

    return DeniedAccess;
}

static ACCESS_MASK GetThreadDeniedAccess(ULONG Operations) {
    ACCESS_MASK DeniedAccess = 0;

    if (Operations & OP_THREAD_SET_CONTEXT) DeniedAccess |= THREAD_SET_CONTEXT;
    if (Operations & OP_TERMINATE) DeniedAccess |= THREAD_TERMINATE;
    if (Operations & OP_SUSPEND_RESUME) DeniedAccess |= THREAD_SUSPEND_RESUME;
    if (Operations & OP_SET_INFORMATION) DeniedAccess |= THREAD_SET_INFORMATION;
    if (Operations & OP_THREAD_SET_TOKEN) DeniedAccess |= THREAD_SET_THREAD_TOKEN;
    if (Operations & OP_IMPERSONATE) DeniedAccess |= THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION;

    return DeniedAccess;
}

static BOOLEAN IsProcessIdentityCurrent(HANDLE ProcessId, PEPROCESS ExpectedProcess);

static VOID ReleaseMemoryWork(PMEMORY_WORK_ITEM Work) {
    if (!Work) return;

    if (Work->TargetProcess) ObDereferenceObject(Work->TargetProcess);
    if (Work->SourceProcess) ObDereferenceObject(Work->SourceProcess);
    InterlockedDecrement(&g_PendingMemoryWork);
    PyasFree(Work);
}

static PMEMORY_WORK_ITEM PopMemoryWork() {
    PMEMORY_WORK_ITEM Work = NULL;
    KIRQL OldIrql;
    KeAcquireSpinLock(&g_MemoryWorkLock, &OldIrql);

    if (!IsListEmpty(&g_MemoryWorkQueue)) {
        PLIST_ENTRY Entry = RemoveHeadList(&g_MemoryWorkQueue);
        Work = CONTAINING_RECORD(Entry, MEMORY_WORK_ITEM, Entry);
    }

    KeReleaseSpinLock(&g_MemoryWorkLock, OldIrql);
    return Work;
}

static VOID CancelQueuedMemoryWork() {
    for (;;) {
        PMEMORY_WORK_ITEM Work = PopMemoryWork();
        if (!Work) return;
        ReleaseMemoryWork(Work);
    }
}

static BOOLEAN QueueMemoryWork(PMEMORY_WORK_ITEM Work) {
    if (!Work) return FALSE;

    LONG Pending = InterlockedIncrement(&g_PendingMemoryWork);
    if (Pending > MAX_PENDING_MEMORY_WORK) {
        InterlockedDecrement(&g_PendingMemoryWork);
        return FALSE;
    }

    KIRQL OldIrql;
    KeAcquireSpinLock(&g_MemoryWorkLock, &OldIrql);

    if (InterlockedCompareExchange(&g_MemoryStopping, 0, 0) != 0) {
        KeReleaseSpinLock(&g_MemoryWorkLock, OldIrql);
        InterlockedDecrement(&g_PendingMemoryWork);
        return FALSE;
    }

    InsertTailList(&g_MemoryWorkQueue, &Work->Entry);
    KeReleaseSpinLock(&g_MemoryWorkLock, OldIrql);
    KeReleaseSemaphore(&g_MemoryWorkSemaphore, IO_NO_INCREMENT, 1, FALSE);
    return TRUE;
}

static VOID DeliverViolation(PMEMORY_WORK_ITEM Work) {
    if (!Work) return;
    if (InterlockedCompareExchange(&g_MemoryStopping, 0, 0) != 0) return;

    BOOLEAN SourceMatches = IsProcessIdentityCurrent(Work->SourcePid, Work->SourceProcess);
    BOOLEAN TargetMatches = IsProcessIdentityCurrent(Work->TargetPid, Work->TargetProcess);
    if (!SourceMatches || !TargetMatches) return;

    PUNICODE_STRING TargetPath = NULL;

    if (NT_SUCCESS(GetProcessImageName(Work->TargetPid, &TargetPath)) && TargetPath && TargetPath->Buffer) {
        SendMessageToUser(
            Work->RuleCode,
            (ULONG)(ULONG_PTR)Work->SourcePid,
            TargetPath->Buffer,
            TargetPath->Length
        );
    }
    else {
        UNICODE_STRING MessageString;
        RtlInitUnicodeString(&MessageString, Work->FallbackMessage);
        SendMessageToUser(
            Work->RuleCode,
            (ULONG)(ULONG_PTR)Work->SourcePid,
            MessageString.Buffer,
            MessageString.Length
        );
    }

    if (TargetPath) ExFreePool(TargetPath);
    QueueRuleProcessTermination(Work->SourcePid, Work->Kill);
}

static VOID ReportViolation(
    ULONG RuleCode,
    BOOLEAN Kill,
    HANDLE SourcePid,
    HANDLE TargetPid,
    PCWSTR FallbackMessage
) {
    if (!RuleCode || !SourcePid || !TargetPid || !FallbackMessage) return;
    if (InterlockedCompareExchange(&g_MemoryStopping, 0, 0) != 0) return;

    PEPROCESS SourceProcess = NULL;
    PEPROCESS TargetProcess = NULL;

    NTSTATUS Status = PsLookupProcessByProcessId(SourcePid, &SourceProcess);
    if (NT_SUCCESS(Status)) {
        Status = PsLookupProcessByProcessId(TargetPid, &TargetProcess);
    }

    if (!NT_SUCCESS(Status)) {
        if (SourceProcess) ObDereferenceObject(SourceProcess);
        return;
    }

    PMEMORY_WORK_ITEM Work = (PMEMORY_WORK_ITEM)PyasAllocate(sizeof(MEMORY_WORK_ITEM));
    if (!Work) {
        ObDereferenceObject(TargetProcess);
        ObDereferenceObject(SourceProcess);
        return;
    }

    RtlZeroMemory(Work, sizeof(*Work));
    Work->Type = MemoryWorkViolationReport;
    Work->SourceProcess = SourceProcess;
    Work->TargetProcess = TargetProcess;
    Work->SourcePid = SourcePid;
    Work->TargetPid = TargetPid;
    Work->RuleCode = RuleCode;
    Work->Kill = Kill;
    RtlStringCchCopyW(Work->FallbackMessage, RTL_NUMBER_OF(Work->FallbackMessage), FallbackMessage);

    if (!QueueMemoryWork(Work)) {
        ObDereferenceObject(TargetProcess);
        ObDereferenceObject(SourceProcess);
        PyasFree(Work);
    }
}

static BOOLEAN IsExecuteProtection(ULONG Protect) {
    ULONG BaseProtect = Protect & 0xFF;

    return BaseProtect == PAGE_EXECUTE ||
        BaseProtect == PAGE_EXECUTE_READ ||
        BaseProtect == PAGE_EXECUTE_READWRITE ||
        BaseProtect == PAGE_EXECUTE_WRITECOPY;
}

static BOOLEAN IsExecuteWriteProtection(ULONG Protect) {
    ULONG BaseProtect = Protect & 0xFF;

    return BaseProtect == PAGE_EXECUTE_READWRITE ||
        BaseProtect == PAGE_EXECUTE_WRITECOPY;
}

static BOOLEAN QueryThreadMemoryRegionForProcess(
    PEPROCESS Process,
    PVOID Address,
    PTHREAD_MEMORY_REGION Region
) {
    if (!Process || !Region || !Address || KeGetCurrentIrql() != PASSIVE_LEVEL) return FALSE;

    RtlZeroMemory(Region, sizeof(*Region));

    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);

    MEMORY_BASIC_INFORMATION MemoryInformation = { 0 };
    SIZE_T ReturnLength = 0;
    NTSTATUS Status = ZwQueryVirtualMemory(
        ZwCurrentProcess(),
        Address,
        MemoryBasicInformation,
        &MemoryInformation,
        sizeof(MemoryInformation),
        &ReturnLength
    );

    KeUnstackDetachProcess(&ApcState);

    if (!NT_SUCCESS(Status)) return FALSE;
    if (MemoryInformation.State != MEM_COMMIT) return FALSE;
    if (!IsExecuteProtection(MemoryInformation.Protect)) return FALSE;

    Region->StartAddress = Address;
    Region->RegionSize = MemoryInformation.RegionSize;

    if (MemoryInformation.Type == MEM_PRIVATE) Region->MemoryType = PYAS_MEMORY_PRIVATE;
    else if (MemoryInformation.Type == MEM_MAPPED) Region->MemoryType = PYAS_MEMORY_MAPPED;
    else if (MemoryInformation.Type == PYAS_MEM_IMAGE_TYPE) Region->MemoryType = PYAS_MEMORY_IMAGE;
    else return FALSE;

    Region->MemoryProtection = PYAS_PROTECT_EXECUTE;
    if (IsExecuteWriteProtection(MemoryInformation.Protect)) {
        Region->MemoryProtection |= PYAS_PROTECT_EXECUTE_WRITE;
    }

    return TRUE;
}

static BOOLEAN QueryThreadMemoryRegion(
    HANDLE ProcessId,
    PVOID Address,
    PTHREAD_MEMORY_REGION Region
) {
    if (!ProcessId) return FALSE;

    PEPROCESS Process = NULL;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) return FALSE;

    BOOLEAN Result = QueryThreadMemoryRegionForProcess(Process, Address, Region);
    ObDereferenceObject(Process);
    return Result;
}

BOOLEAN IsAddressInUnmappedMemory(HANDLE ProcessId, PVOID Address) {
    THREAD_MEMORY_REGION Region = { 0 };
    if (!QueryThreadMemoryRegion(ProcessId, Address, &Region)) return FALSE;
    return Region.MemoryType == PYAS_MEMORY_PRIVATE;
}

static BOOLEAN IsProcessIdentityCurrent(HANDLE ProcessId, PEPROCESS ExpectedProcess) {
    if (!ProcessId || !ExpectedProcess) return FALSE;

    PEPROCESS CurrentProcess = NULL;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &CurrentProcess);
    if (!NT_SUCCESS(Status)) return FALSE;

    BOOLEAN Matches = CurrentProcess == ExpectedProcess;
    ObDereferenceObject(CurrentProcess);
    return Matches;
}

static OB_PREOP_CALLBACK_STATUS ObjectPreCallbackCore(
    POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    if (!OperationInformation || OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    PACCESS_MASK DesiredAccess = GetDesiredAccessPointer(OperationInformation);
    ULONG HandleType = GetHandleType(OperationInformation);

    if (!DesiredAccess || *DesiredAccess == 0 || HandleType == 0) {
        return OB_PREOP_SUCCESS;
    }

    HANDLE SourcePid = PsGetCurrentProcessId();
    if (!SourcePid || IsProcessTrusted(SourcePid)) {
        return OB_PREOP_SUCCESS;
    }

    HANDLE TargetPid = NULL;
    ULONG ObjectType = 0;
    ULONG RequestedOperations = 0;
    ACCESS_MASK OriginalAccess = *DesiredAccess;

    if (OperationInformation->ObjectType == *PsProcessType) {
        TargetPid = PsGetProcessId((PEPROCESS)OperationInformation->Object);
        ObjectType = PYAS_OBJECT_PROCESS;
        RequestedOperations = GetProcessOperations(OriginalAccess);
    }
    else if (OperationInformation->ObjectType == *PsThreadType) {
        TargetPid = PsGetThreadProcessId((PETHREAD)OperationInformation->Object);
        ObjectType = PYAS_OBJECT_THREAD;
        RequestedOperations = GetThreadOperations(OriginalAccess);
    }
    else {
        return OB_PREOP_SUCCESS;
    }

    if (!TargetPid || SourcePid == TargetPid || RequestedOperations == 0) {
        return OB_PREOP_SUCCESS;
    }

    ULONG DeniedOperations = 0;
    ULONG RuleCode = 0;
    BOOLEAN Kill = FALSE;

    if (!EvaluateProcessAccessRule(
        SourcePid,
        TargetPid,
        RequestedOperations,
        HandleType,
        ObjectType,
        &DeniedOperations,
        &RuleCode,
        &Kill
    )) {
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK DeniedAccess = ObjectType == PYAS_OBJECT_PROCESS
        ? GetProcessDeniedAccess(DeniedOperations)
        : GetThreadDeniedAccess(DeniedOperations);

    ACCESS_MASK EffectiveDeniedAccess = OriginalAccess & DeniedAccess;
    if (EffectiveDeniedAccess == 0) return OB_PREOP_SUCCESS;

    *DesiredAccess = OriginalAccess & ~EffectiveDeniedAccess;

    ReportViolation(
        RuleCode,
        Kill,
        SourcePid,
        TargetPid,
        ObjectType == PYAS_OBJECT_PROCESS
        ? L"Process_Handle_Access_Denied"
        : L"Thread_Handle_Access_Denied"
    );

    return OB_PREOP_SUCCESS;
}

static OB_PREOP_CALLBACK_STATUS ObjectPreCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!g_MemoryProtectionInitialized) return OB_PREOP_SUCCESS;
    if (InterlockedCompareExchange(&g_MemoryStopping, 0, 0) != 0) return OB_PREOP_SUCCESS;
    if (!ExAcquireRundownProtection(&g_MemoryRundown)) return OB_PREOP_SUCCESS;

    OB_PREOP_CALLBACK_STATUS Result = ObjectPreCallbackCore(OperationInformation);
    ExReleaseRundownProtection(&g_MemoryRundown);
    return Result;
}

static VOID ProcessThreadAnalysis(PMEMORY_WORK_ITEM Work) {
    if (!Work) return;
    if (InterlockedCompareExchange(&g_MemoryStopping, 0, 0) != 0) return;

    PVOID StartAddress = NULL;
    HANDLE ThreadHandle = NULL;
    BOOLEAN IdentityValid =
        IsProcessIdentityCurrent(Work->SourcePid, Work->SourceProcess) &&
        IsProcessIdentityCurrent(Work->TargetPid, Work->TargetProcess);
    CLIENT_ID ClientId = { Work->TargetPid, Work->ThreadId };
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS Status = STATUS_PROCESS_IS_TERMINATING;
    if (IdentityValid) {
        Status = ZwOpenThread(
            &ThreadHandle,
            THREAD_QUERY_INFORMATION,
            &ObjectAttributes,
            &ClientId
        );
    }

    if (NT_SUCCESS(Status)) {
        Status = ZwQueryInformationThread(
            ThreadHandle,
            (THREADINFOCLASS)THREAD_QUERY_SET_WIN32_START_ADDRESS,
            &StartAddress,
            sizeof(StartAddress),
            NULL
        );
        ZwClose(ThreadHandle);
    }

    if (!NT_SUCCESS(Status) || !StartAddress) return;
    if (InterlockedCompareExchange(&g_MemoryStopping, 0, 0) != 0) return;

    THREAD_MEMORY_REGION Region = { 0 };
    if (!QueryThreadMemoryRegionForProcess(Work->TargetProcess, StartAddress, &Region)) return;

    ULONG RuleCode = 0;
    BOOLEAN Kill = FALSE;
    if (!EvaluateThreadRule(
        Work->SourcePid,
        Work->TargetPid,
        StartAddress,
        Region.MemoryType,
        Region.MemoryProtection,
        Region.RegionSize,
        &RuleCode,
        &Kill
    )) {
        return;
    }

    Work->RuleCode = RuleCode;
    Work->Kill = Kill;
    RtlStringCchCopyW(
        Work->FallbackMessage,
        RTL_NUMBER_OF(Work->FallbackMessage),
        L"Remote_Executable_Thread_Detected"
    );
    DeliverViolation(Work);
}

static VOID MemoryWorkerThread(PVOID Parameter) {
    UNREFERENCED_PARAMETER(Parameter);

    for (;;) {
        KeWaitForSingleObject(
            &g_MemoryWorkSemaphore,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );

        if (InterlockedCompareExchange(&g_MemoryStopping, 0, 0) != 0) {
            CancelQueuedMemoryWork();
            break;
        }

        PMEMORY_WORK_ITEM Work = PopMemoryWork();
        if (!Work) continue;

        if (Work->Type == MemoryWorkThreadAnalysis) {
            ProcessThreadAnalysis(Work);
        }
        else if (Work->Type == MemoryWorkViolationReport) {
            DeliverViolation(Work);
        }

        ReleaseMemoryWork(Work);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID ThreadNotifyCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN IsCreated
) {
    if (!IsCreated || !g_MemoryProtectionInitialized) return;
    if (InterlockedCompareExchange(&g_MemoryStopping, 0, 0) != 0) return;

    HANDLE SourcePid = PsGetCurrentProcessId();
    if (!SourcePid || SourcePid == ProcessId || IsProcessTrusted(SourcePid)) return;

    PEPROCESS SourceProcess = PsGetCurrentProcess();
    PEPROCESS TargetProcess = NULL;
    ObReferenceObject(SourceProcess);

    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &TargetProcess);
    if (!NT_SUCCESS(Status)) {
        ObDereferenceObject(SourceProcess);
        return;
    }

    PMEMORY_WORK_ITEM Work = (PMEMORY_WORK_ITEM)PyasAllocate(sizeof(MEMORY_WORK_ITEM));
    if (!Work) {
        ObDereferenceObject(TargetProcess);
        ObDereferenceObject(SourceProcess);
        return;
    }

    RtlZeroMemory(Work, sizeof(*Work));
    Work->Type = MemoryWorkThreadAnalysis;
    Work->SourceProcess = SourceProcess;
    Work->TargetProcess = TargetProcess;
    Work->SourcePid = SourcePid;
    Work->TargetPid = ProcessId;
    Work->ThreadId = ThreadId;

    if (!QueueMemoryWork(Work)) {
        ObDereferenceObject(TargetProcess);
        ObDereferenceObject(SourceProcess);
        PyasFree(Work);
    }
}

static VOID LoadImageNotifyCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
) {
    if (!g_MemoryProtectionInitialized) return;
    if (InterlockedCompareExchange(&g_MemoryStopping, 0, 0) != 0) return;
    if (!FullImageName || !FullImageName->Buffer || !ImageInfo || ImageInfo->SystemModeImage) return;
    if (!ProcessId || !ExAcquireRundownProtection(&g_MemoryRundown)) return;

    ULONG RuleCode = 0;
    BOOLEAN Kill = FALSE;
    if (EvaluateImageLoadRule(ProcessId, FullImageName, ImageInfo, &RuleCode, &Kill)) {
        SendMessageToUser(
            RuleCode,
            (ULONG)(ULONG_PTR)ProcessId,
            FullImageName->Buffer,
            FullImageName->Length
        );
        QueueRuleProcessTermination(ProcessId, Kill);
    }

    ExReleaseRundownProtection(&g_MemoryRundown);
}

static NTSTATUS RemoveMemoryCallbacks() {
    NTSTATUS FirstFailure = STATUS_SUCCESS;

    if (GlobalData.ObRegistrationHandle) {
        ObUnRegisterCallbacks(GlobalData.ObRegistrationHandle);
        GlobalData.ObRegistrationHandle = NULL;
    }

    if (g_ThreadNotifyRegistered) {
        NTSTATUS Status = PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        if (NT_SUCCESS(Status) || Status == STATUS_PROCEDURE_NOT_FOUND) {
            g_ThreadNotifyRegistered = FALSE;
        }
        else if (NT_SUCCESS(FirstFailure)) {
            FirstFailure = Status;
        }
    }

    if (g_LoadImageNotifyRegistered) {
        NTSTATUS Status = PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);
        if (NT_SUCCESS(Status) || Status == STATUS_PROCEDURE_NOT_FOUND) {
            g_LoadImageNotifyRegistered = FALSE;
        }
        else if (NT_SUCCESS(FirstFailure)) {
            FirstFailure = Status;
        }
    }

    return FirstFailure;
}

static NTSTATUS StartMemoryWorker() {
    if (g_MemoryWorkerHandle) return STATUS_SUCCESS;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(
        &ObjectAttributes,
        NULL,
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    return PsCreateSystemThread(
        &g_MemoryWorkerHandle,
        SYNCHRONIZE,
        &ObjectAttributes,
        NULL,
        NULL,
        MemoryWorkerThread,
        NULL
    );
}

static NTSTATUS StopMemoryWorker(BOOLEAN WaitWithoutTimeout) {
    CancelQueuedMemoryWork();

    if (!g_MemoryWorkerHandle) return STATUS_SUCCESS;

    KeReleaseSemaphore(&g_MemoryWorkSemaphore, IO_NO_INCREMENT, 1, FALSE);

    LARGE_INTEGER Timeout;
    PLARGE_INTEGER TimeoutPointer = NULL;

    if (!WaitWithoutTimeout) {
        Timeout.QuadPart = -((LONGLONG)MEMORY_WORKER_STOP_TIMEOUT_MS * 10 * 1000);
        TimeoutPointer = &Timeout;
    }

    NTSTATUS Status = ZwWaitForSingleObject(
        g_MemoryWorkerHandle,
        FALSE,
        TimeoutPointer
    );

    if (Status == STATUS_TIMEOUT) return STATUS_DEVICE_BUSY;
    if (!NT_SUCCESS(Status)) return Status;

    ZwClose(g_MemoryWorkerHandle);
    g_MemoryWorkerHandle = NULL;
    return STATUS_SUCCESS;
}

NTSTATUS InitializeMemoryProtection(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_MemoryProtectionInitialized) return STATUS_SUCCESS;

    InitializeListHead(&g_MemoryWorkQueue);
    KeInitializeSpinLock(&g_MemoryWorkLock);
    KeInitializeSemaphore(&g_MemoryWorkSemaphore, 0, MAXLONG);
    ExInitializeRundownProtection(&g_MemoryRundown);
    g_MemoryRundownCompleted = FALSE;
    InterlockedExchange(&g_PendingMemoryWork, 0);
    InterlockedExchange(&g_MemoryStopping, 0);
    g_MemoryProtectionInitialized = TRUE;

    NTSTATUS Status = StartMemoryWorker();
    if (!NT_SUCCESS(Status)) {
        InterlockedExchange(&g_MemoryStopping, 1);
        g_MemoryProtectionInitialized = FALSE;
        return Status;
    }

    Status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (!NT_SUCCESS(Status)) {
        InterlockedExchange(&g_MemoryStopping, 1);
        StopMemoryWorker(TRUE);
        g_MemoryProtectionInitialized = FALSE;
        return Status;
    }
    g_ThreadNotifyRegistered = TRUE;

    Status = PsSetLoadImageNotifyRoutine(LoadImageNotifyCallback);
    if (!NT_SUCCESS(Status)) {
        InterlockedExchange(&g_MemoryStopping, 1);
        RemoveMemoryCallbacks();
        ExWaitForRundownProtectionRelease(&g_MemoryRundown);
        g_MemoryRundownCompleted = TRUE;
        StopMemoryWorker(TRUE);
        g_MemoryProtectionInitialized = FALSE;
        return Status;
    }
    g_LoadImageNotifyRegistered = TRUE;

    OB_OPERATION_REGISTRATION OperationRegistration[2] = { 0 };
    OperationRegistration[0].ObjectType = PsProcessType;
    OperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OperationRegistration[0].PreOperation = ObjectPreCallback;

    OperationRegistration[1].ObjectType = PsThreadType;
    OperationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OperationRegistration[1].PreOperation = ObjectPreCallback;

    OB_CALLBACK_REGISTRATION CallbackRegistration = { 0 };
    CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    CallbackRegistration.OperationRegistrationCount = RTL_NUMBER_OF(OperationRegistration);
    CallbackRegistration.OperationRegistration = OperationRegistration;
    RtlInitUnicodeString(&CallbackRegistration.Altitude, PYAS_OB_ALTITUDE);

    Status = ObRegisterCallbacks(&CallbackRegistration, &GlobalData.ObRegistrationHandle);
    if (NT_SUCCESS(Status)) return STATUS_SUCCESS;

    InterlockedExchange(&g_MemoryStopping, 1);
    RemoveMemoryCallbacks();
    ExWaitForRundownProtectionRelease(&g_MemoryRundown);
    g_MemoryRundownCompleted = TRUE;
    StopMemoryWorker(TRUE);
    g_MemoryProtectionInitialized = FALSE;
    return Status;
}

NTSTATUS UninitializeMemoryProtection(BOOLEAN WaitWithoutTimeout) {
    if (!g_MemoryProtectionInitialized) return STATUS_SUCCESS;

    InterlockedExchange(&g_MemoryStopping, 1);

    NTSTATUS CallbackStatus = RemoveMemoryCallbacks();

    if (!g_MemoryRundownCompleted) {
        ExWaitForRundownProtectionRelease(&g_MemoryRundown);
        g_MemoryRundownCompleted = TRUE;
    }

    NTSTATUS WorkerStatus = StopMemoryWorker(WaitWithoutTimeout);
    if (!NT_SUCCESS(CallbackStatus)) return CallbackStatus;
    if (!NT_SUCCESS(WorkerStatus)) return WorkerStatus;

    if (g_ThreadNotifyRegistered || g_LoadImageNotifyRegistered || GlobalData.ObRegistrationHandle) {
        return STATUS_DEVICE_BUSY;
    }

    g_MemoryProtectionInitialized = FALSE;
    return STATUS_SUCCESS;
}

