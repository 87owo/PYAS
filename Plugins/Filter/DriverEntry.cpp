#include "DriverCommon.h"

DRIVER_DATA GlobalData;
static BOOLEAN g_ProcessNotifyRegistered = FALSE;
static BOOLEAN g_ProcessProtectionInitialized = FALSE;
static BOOLEAN g_RegistryProtectionInitialized = FALSE;
static BOOLEAN g_RulesEngineInitialized = FALSE;

static NTSTATUS InstanceSetup(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE VolumeDeviceType,
    FLT_FILESYSTEM_TYPE VolumeFilesystemType
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

static NTSTATUS InstanceQueryTeardown(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

static VOID InstanceTeardownStart(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_TEARDOWN_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

static VOID InstanceTeardownComplete(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_TEARDOWN_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

static NTSTATUS SelectFailure(NTSTATUS CurrentStatus, NTSTATUS CandidateStatus) {
    if (!NT_SUCCESS(CurrentStatus)) return CurrentStatus;
    return CandidateStatus;
}

static NTSTATUS UnregisterRuntimeCallbacksPass(BOOLEAN WaitWithoutTimeout) {
    NTSTATUS Status = STATUS_SUCCESS;

    NTSTATUS MemoryStatus = UninitializeMemoryProtection(WaitWithoutTimeout);
    if (!NT_SUCCESS(MemoryStatus)) {
        Status = SelectFailure(Status, MemoryStatus);
    }

    if (g_ProcessNotifyRegistered) {
        NTSTATUS ProcessNotifyStatus = PsSetCreateProcessNotifyRoutineEx(
            ProcessNotifyCallbackEx,
            TRUE
        );

        if (NT_SUCCESS(ProcessNotifyStatus) || ProcessNotifyStatus == STATUS_INVALID_PARAMETER) {
            g_ProcessNotifyRegistered = FALSE;
        }
        else {
            Status = SelectFailure(Status, ProcessNotifyStatus);
        }
    }

    if (!g_ProcessNotifyRegistered && g_ProcessProtectionInitialized) {
        NTSTATUS ProcessStatus = UninitializeProcessProtection();
        if (NT_SUCCESS(ProcessStatus)) {
            g_ProcessProtectionInitialized = FALSE;
        }
        else {
            Status = SelectFailure(Status, ProcessStatus);
        }
    }

    if (g_RegistryProtectionInitialized) {
        NTSTATUS RegistryStatus = UninitializeRegistryProtection();
        if (NT_SUCCESS(RegistryStatus)) {
            g_RegistryProtectionInitialized = FALSE;
        }
        else {
            Status = SelectFailure(Status, RegistryStatus);
        }
    }

    return Status;
}

static NTSTATUS UnregisterRuntimeCallbacks(BOOLEAN WaitWithoutTimeout) {
    for (;;) {
        NTSTATUS Status = UnregisterRuntimeCallbacksPass(WaitWithoutTimeout);
        if (NT_SUCCESS(Status) || !WaitWithoutTimeout) return Status;

        LARGE_INTEGER Delay;
        Delay.QuadPart = -(10LL * 10 * 1000);
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }
}

static PEPROCESS DetachConnectedProcessReference(PEPROCESS ExpectedProcess) {
    PEPROCESS Process = NULL;

    KIRQL OldIrql;
    KeAcquireSpinLock(&GlobalData.PortMutex, &OldIrql);

    if (!ExpectedProcess || GlobalData.PyasProcess == ExpectedProcess) {
        Process = GlobalData.PyasProcess;
        GlobalData.PyasProcess = NULL;
    }

    KeReleaseSpinLock(&GlobalData.PortMutex, OldIrql);
    return Process;
}

static VOID ReleaseConnectedProcessReference() {
    PEPROCESS Process = DetachConnectedProcessReference(NULL);

    SafeSetPyasPid(0);
    InterlockedExchange(&GlobalData.UnloadAuthorized, 0);

    if (Process) {
        ObDereferenceObject(Process);
    }
}

static VOID CloseCurrentClientPort() {
    if (InterlockedCompareExchange(&GlobalData.ClientCloseActive, 1, 0) != 0) return;

    PFLT_FILTER FilterHandle = NULL;
    PFLT_PORT ClientPort = NULL;

    KIRQL OldIrql;
    KeAcquireSpinLock(&GlobalData.PortMutex, &OldIrql);
    FilterHandle = GlobalData.FilterHandle;
    ClientPort = GlobalData.ClientPort;
    GlobalData.ClientPort = NULL;
    KeReleaseSpinLock(&GlobalData.PortMutex, OldIrql);

    if (FilterHandle && ClientPort) {
        FltCloseClientPort(FilterHandle, &ClientPort);
    }

    InterlockedExchange(&GlobalData.ClientCloseActive, 0);
}

static VOID WaitForClientPortClose() {
    LARGE_INTEGER Delay;
    Delay.QuadPart = -(10LL * 1000);

    while (InterlockedCompareExchange(&GlobalData.ClientCloseActive, 0, 0) != 0) {
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }
}

static VOID ReleaseFilterResources() {
    InterlockedExchange(&GlobalData.PortStopping, 1);

    if (GlobalData.ServerPort) {
        PFLT_PORT ServerPort = GlobalData.ServerPort;
        GlobalData.ServerPort = NULL;
        FltCloseCommunicationPort(ServerPort);
    }

    CloseCurrentClientPort();
    WaitForClientPortClose();
    ExWaitForRundownProtectionRelease(&GlobalData.PortRundown);

    if (GlobalData.FilterHandle) {
        PFLT_FILTER FilterHandle = GlobalData.FilterHandle;
        FltUnregisterFilter(FilterHandle);
        GlobalData.FilterHandle = NULL;
    }

    ReleaseConnectedProcessReference();
}

static NTSTATUS CleanupDriverState(BOOLEAN WaitWithoutTimeout) {
    NTSTATUS Status = UnregisterRuntimeCallbacks(WaitWithoutTimeout);
    if (!NT_SUCCESS(Status)) return Status;

    GlobalData.Initialized = FALSE;
    ReleaseFilterResources();

    if (g_RulesEngineInitialized) {
        UnloadRules();
        UninitializeRulesEngine();
        g_RulesEngineInitialized = FALSE;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS BeginUnload(BOOLEAN MandatoryUnload) {
    for (;;) {
        LONG State = InterlockedCompareExchange(
            &GlobalData.DriverState,
            PyasDriverStateCold,
            PyasDriverStateCold
        );

        if (State == PyasDriverStateStopped) return STATUS_SUCCESS;

        if (State == PyasDriverStateStopping) {
            LARGE_INTEGER Timeout;
            PLARGE_INTEGER TimeoutPointer = NULL;

            if (!MandatoryUnload) {
                Timeout.QuadPart = -(2LL * 10 * 1000 * 1000);
                TimeoutPointer = &Timeout;
            }

            NTSTATUS WaitStatus = KeWaitForSingleObject(
                &GlobalData.CleanupCompleteEvent,
                Executive,
                KernelMode,
                FALSE,
                TimeoutPointer
            );

            if (!MandatoryUnload && WaitStatus == STATUS_TIMEOUT) {
                return STATUS_DEVICE_BUSY;
            }

            if (!NT_SUCCESS(WaitStatus)) return WaitStatus;
            continue;
        }

        if (State != PyasDriverStateRunning && State != PyasDriverStateStopRetry) {
            return STATUS_DEVICE_NOT_READY;
        }

        if (!MandatoryUnload && InterlockedCompareExchange(&GlobalData.UnloadAuthorized, 0, 1) != 1) {
            return STATUS_ACCESS_DENIED;
        }

        if (MandatoryUnload) {
            InterlockedExchange(&GlobalData.UnloadAuthorized, 0);
        }

        if (InterlockedCompareExchange(
            &GlobalData.DriverState,
            PyasDriverStateStopping,
            State
        ) != State) {
            if (!MandatoryUnload) return STATUS_DEVICE_BUSY;
            continue;
        }

        KeClearEvent(&GlobalData.CleanupCompleteEvent);
        return STATUS_SUCCESS;
    }
}

static NTSTATUS DriverUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    BOOLEAN MandatoryUnload = FlagOn(Flags, FLTFL_FILTER_UNLOAD_MANDATORY) ? TRUE : FALSE;

    NTSTATUS Status = BeginUnload(MandatoryUnload);
    if (!NT_SUCCESS(Status)) return Status;

    LONG State = InterlockedCompareExchange(
        &GlobalData.DriverState,
        PyasDriverStateCold,
        PyasDriverStateCold
    );

    if (State == PyasDriverStateStopped) return STATUS_SUCCESS;

    Status = CleanupDriverState(MandatoryUnload);

    InterlockedExchange(
        &GlobalData.DriverState,
        NT_SUCCESS(Status) ? PyasDriverStateStopped : PyasDriverStateStopRetry
    );

    KeSetEvent(&GlobalData.CleanupCompleteEvent, IO_NO_INCREMENT, FALSE);
    return Status;
}

static NTSTATUS PortMessage(
    PVOID PortCookie,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG ReturnOutputBufferLength
) {
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;

    if (InterlockedCompareExchange(&GlobalData.PortStopping, 0, 0) != 0) {
        return STATUS_DELETE_PENDING;
    }

    if (!ExAcquireRundownProtection(&GlobalData.PortRundown)) {
        return STATUS_DELETE_PENDING;
    }

    NTSTATUS Status = STATUS_SUCCESS;
    PYAS_USER_MESSAGE Message = { 0 };
    UNICODE_STRING Path = { 0 };
    LONG DriverState = PyasDriverStateCold;
    ULONG StateValue = PyasDriverStateCold;

    if (!PortCookie || PortCookie != GlobalData.PyasProcess) {
        Status = STATUS_ACCESS_DENIED;
        goto Exit;
    }

    if (!InputBuffer || InputBufferLength < sizeof(PYAS_USER_MESSAGE)) {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    __try {
        RtlCopyMemory(&Message, InputBuffer, sizeof(Message));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        goto Exit;
    }

    Message.Path[MAX_PATH_LEN - 1] = L'\0';

    if (Message.Command == PyasCommandQueryState) {
        if (!OutputBuffer || OutputBufferLength < sizeof(ULONG) || !ReturnOutputBufferLength) {
            Status = STATUS_BUFFER_TOO_SMALL;
            goto Exit;
        }

        StateValue = (ULONG)InterlockedCompareExchange(
            &GlobalData.DriverState,
            PyasDriverStateCold,
            PyasDriverStateCold
        );

        __try {
            *(PULONG)OutputBuffer = StateValue;
            *ReturnOutputBufferLength = sizeof(ULONG);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }
        goto Exit;
    }

    if (Message.Command == PyasCommandAuthorizeUnload) {
        DriverState = InterlockedCompareExchange(
            &GlobalData.DriverState,
            PyasDriverStateCold,
            PyasDriverStateCold
        );

        if (DriverState != PyasDriverStateRunning && DriverState != PyasDriverStateStopRetry) {
            Status = STATUS_DEVICE_NOT_READY;
            goto Exit;
        }

        InterlockedExchange(&GlobalData.UnloadAuthorized, 1);
        goto Exit;
    }

    if (Message.Command == PyasCommandRevokeUnload) {
        InterlockedExchange(&GlobalData.UnloadAuthorized, 0);
        goto Exit;
    }

    if (Message.Command < PyasCommandAddWhitelist || Message.Command > PyasCommandClearRules) {
        Status = STATUS_INVALID_DEVICE_REQUEST;
        goto Exit;
    }

    DriverState = InterlockedCompareExchange(
        &GlobalData.DriverState,
        PyasDriverStateCold,
        PyasDriverStateCold
    );

    if (DriverState != PyasDriverStateRunning) {
        Status = STATUS_DEVICE_NOT_READY;
        goto Exit;
    }

    RtlInitUnicodeString(&Path, Message.Path);

    if (Message.Command == PyasCommandAddWhitelist) {
        if (Path.Length == 0) {
            Status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        AddDynamicWhitelist(&Path);
        goto Exit;
    }

    if (Message.Command == PyasCommandRemoveWhitelist) {
        if (Path.Length == 0) {
            Status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        RemoveDynamicWhitelist(&Path);
        goto Exit;
    }

    if (Message.Command == PyasCommandLoadRuleFile) {
        if (Path.Length == 0) {
            Status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        Status = LoadRuleFile(&Path);
        goto Exit;
    }

    ClearDynamicRules();

Exit:
    ExReleaseRundownProtection(&GlobalData.PortRundown);
    return Status;
}

static NTSTATUS PortConnect(
    PFLT_PORT ClientPort,
    PVOID ServerPortCookie,
    PVOID ConnectionContext,
    ULONG SizeOfContext,
    PVOID* ConnectionPortCookie
) {
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    if (!ConnectionPortCookie) return STATUS_INVALID_PARAMETER;
    *ConnectionPortCookie = NULL;

    if (InterlockedCompareExchange(&GlobalData.PortStopping, 0, 0) != 0) {
        return STATUS_DELETE_PENDING;
    }

    LONG DriverState = InterlockedCompareExchange(
        &GlobalData.DriverState,
        PyasDriverStateCold,
        PyasDriverStateCold
    );

    if (DriverState != PyasDriverStateRunning && DriverState != PyasDriverStateStopRetry) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!ExAcquireRundownProtection(&GlobalData.PortRundown)) {
        return STATUS_DELETE_PENDING;
    }

    PEPROCESS ConnectingProcess = PsGetCurrentProcess();
    ObReferenceObject(ConnectingProcess);

    NTSTATUS Status = STATUS_SUCCESS;
    KIRQL OldIrql;
    KeAcquireSpinLock(&GlobalData.PortMutex, &OldIrql);

    DriverState = InterlockedCompareExchange(
        &GlobalData.DriverState,
        PyasDriverStateCold,
        PyasDriverStateCold
    );

    if (InterlockedCompareExchange(&GlobalData.PortStopping, 0, 0) != 0) {
        Status = STATUS_DELETE_PENDING;
    }
    else if (DriverState != PyasDriverStateRunning && DriverState != PyasDriverStateStopRetry) {
        Status = STATUS_DEVICE_NOT_READY;
    }
    else if (GlobalData.ClientPort || GlobalData.PyasProcess) {
        Status = STATUS_DEVICE_BUSY;
    }
    else {
        GlobalData.ClientPort = ClientPort;
        GlobalData.PyasProcess = ConnectingProcess;
        *ConnectionPortCookie = ConnectingProcess;
    }

    KeReleaseSpinLock(&GlobalData.PortMutex, OldIrql);

    if (!NT_SUCCESS(Status)) {
        ObDereferenceObject(ConnectingProcess);
        ExReleaseRundownProtection(&GlobalData.PortRundown);
        return Status;
    }

    SafeSetPyasPid((ULONG)(ULONG_PTR)PsGetCurrentProcessId());
    InterlockedExchange(&GlobalData.UnloadAuthorized, 0);
    ExReleaseRundownProtection(&GlobalData.PortRundown);
    return STATUS_SUCCESS;
}

static VOID PortDisconnect(PVOID ConnectionCookie) {
    if (!ConnectionCookie) return;

    PEPROCESS Process = DetachConnectedProcessReference((PEPROCESS)ConnectionCookie);
    if (!Process) return;

    CloseCurrentClientPort();
    InterlockedExchange(&GlobalData.UnloadAuthorized, 0);
    SafeSetPyasPid(0);
    ObDereferenceObject(Process);
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, ProtectFile_PreCreate, NULL },
    { IRP_MJ_WRITE, 0, ProtectFile_PreWrite, NULL },
    { IRP_MJ_SET_INFORMATION, 0, ProtectFile_PreSetInfo, NULL },
    { IRP_MJ_SET_SECURITY, 0, ProtectFile_SetSecurity, NULL },
    { IRP_MJ_FILE_SYSTEM_CONTROL, 0, ProtectFile_FileSystemControl, NULL },
    { IRP_MJ_DEVICE_CONTROL, 0, ProtectBoot_PreDeviceControl, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    DriverUnload,
    InstanceSetup,
    InstanceQueryTeardown,
    InstanceTeardownStart,
    InstanceTeardownComplete,
    NULL,
    NULL,
    NULL
};

extern "C" NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
) {
    RtlZeroMemory(&GlobalData, sizeof(GlobalData));
    GlobalData.DriverObject = DriverObject;
    KeInitializeSpinLock(&GlobalData.PortMutex);
    KeInitializeSpinLock(&GlobalData.TrackerMutex);
    KeInitializeSpinLock(&GlobalData.PidLock);
    ExInitializeRundownProtection(&GlobalData.PortRundown);
    KeInitializeEvent(&GlobalData.CleanupCompleteEvent, NotificationEvent, FALSE);
    InterlockedExchange(&GlobalData.PortStopping, 0);
    InterlockedExchange(&GlobalData.ClientCloseActive, 0);
    InterlockedExchange(&GlobalData.DriverState, PyasDriverStateStarting);

    NTSTATUS Status = STATUS_SUCCESS;
    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;

    Status = InitializeRulesEngine();
    if (!NT_SUCCESS(Status)) {
        InterlockedExchange(&GlobalData.DriverState, PyasDriverStateStopped);
        KeSetEvent(&GlobalData.CleanupCompleteEvent, IO_NO_INCREMENT, FALSE);
        return Status;
    }
    g_RulesEngineInitialized = TRUE;

    Status = LoadRulesFromDisk(RegistryPath);
    if (!NT_SUCCESS(Status)) goto Failure;

    Status = FltRegisterFilter(DriverObject, &FilterRegistration, &GlobalData.FilterHandle);
    if (!NT_SUCCESS(Status)) goto Failure;

    Status = FltBuildDefaultSecurityDescriptor(&SecurityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(Status)) goto Failure;

    {
        UNICODE_STRING PortName;
        RtlInitUnicodeString(&PortName, PYAS_PORT_NAME);

        OBJECT_ATTRIBUTES ObjectAttributes;
        InitializeObjectAttributes(
            &ObjectAttributes,
            &PortName,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
            NULL,
            SecurityDescriptor
        );

        Status = FltCreateCommunicationPort(
            GlobalData.FilterHandle,
            &GlobalData.ServerPort,
            &ObjectAttributes,
            NULL,
            PortConnect,
            PortDisconnect,
            PortMessage,
            1
        );
    }

    FltFreeSecurityDescriptor(SecurityDescriptor);
    if (!NT_SUCCESS(Status)) goto Failure;

    Status = InitializeRegistryProtection(DriverObject);
    if (!NT_SUCCESS(Status)) goto Failure;
    g_RegistryProtectionInitialized = TRUE;

    Status = InitializeProcessProtection();
    if (!NT_SUCCESS(Status)) goto Failure;
    g_ProcessProtectionInitialized = TRUE;

    Status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    if (!NT_SUCCESS(Status)) goto Failure;
    g_ProcessNotifyRegistered = TRUE;

    Status = InitializeMemoryProtection(DriverObject);
    if (!NT_SUCCESS(Status)) goto Failure;

    Status = FltStartFiltering(GlobalData.FilterHandle);
    if (!NT_SUCCESS(Status)) goto Failure;

    GlobalData.Initialized = TRUE;
    InterlockedExchange(&GlobalData.DriverState, PyasDriverStateRunning);
    return STATUS_SUCCESS;

Failure:
    CleanupDriverState(TRUE);
    InterlockedExchange(&GlobalData.DriverState, PyasDriverStateStopped);
    KeSetEvent(&GlobalData.CleanupCompleteEvent, IO_NO_INCREMENT, FALSE);
    return Status;
}
