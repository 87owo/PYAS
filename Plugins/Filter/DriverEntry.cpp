#include "DriverCommon.h"

DRIVER_DATA GlobalData;
static BOOLEAN g_ProcessNotifyRegistered = FALSE;
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

static VOID UnregisterRuntimeCallbacks() {
    UninitializeMemoryProtection();

    if (g_ProcessNotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
        g_ProcessNotifyRegistered = FALSE;
    }

    if (g_RegistryProtectionInitialized) {
        UninitializeRegistryProtection();
        g_RegistryProtectionInitialized = FALSE;
    }
}

static VOID ReleaseFilterResources() {
    if (GlobalData.ServerPort) {
        FltCloseCommunicationPort(GlobalData.ServerPort);
        GlobalData.ServerPort = NULL;
    }

    if (GlobalData.FilterHandle) {
        FltUnregisterFilter(GlobalData.FilterHandle);
        GlobalData.FilterHandle = NULL;
    }
}

static VOID CleanupDriverState() {
    GlobalData.Initialized = FALSE;
    UnregisterRuntimeCallbacks();
    ReleaseFilterResources();

    if (g_RulesEngineInitialized) {
        UnloadRules();
        UninitializeRulesEngine();
        g_RulesEngineInitialized = FALSE;
    }
}

static NTSTATUS DriverUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);

    if (InterlockedCompareExchange(&GlobalData.UnloadAuthorized, 0, 1) != 1) {
        return STATUS_ACCESS_DENIED;
    }

    CleanupDriverState();
    return STATUS_SUCCESS;
}

static NTSTATUS PortMessage(
    PVOID PortCookie,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG ReturnOutputBufferLength
) {
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (!PortCookie || PortCookie != GlobalData.PyasProcess) {
        return STATUS_ACCESS_DENIED;
    }

    if (!InputBuffer || InputBufferLength < sizeof(PYAS_USER_MESSAGE)) {
        return STATUS_INVALID_PARAMETER;
    }

    PPYAS_USER_MESSAGE Message = (PPYAS_USER_MESSAGE)InputBuffer;
    Message->Path[MAX_PATH_LEN - 1] = L'\0';

    if (Message->Command == PyasCommandAuthorizeUnload) {
        InterlockedExchange(&GlobalData.UnloadAuthorized, 1);
    }
    else if (Message->Command == PyasCommandRevokeUnload) {
        InterlockedExchange(&GlobalData.UnloadAuthorized, 0);
    }
    else if (Message->Command >= PyasCommandAddWhitelist && Message->Command <= PyasCommandClearRules) {
        UNICODE_STRING Path;
        RtlInitUnicodeString(&Path, Message->Path);

        if (Message->Command == PyasCommandAddWhitelist && Path.Length > 0) {
            AddDynamicWhitelist(&Path);
        }
        else if (Message->Command == PyasCommandRemoveWhitelist && Path.Length > 0) {
            RemoveDynamicWhitelist(&Path);
        }
        else if (Message->Command == PyasCommandLoadRuleFile && Path.Length > 0) {
            LoadRuleFile(&Path);
        }
        else if (Message->Command == PyasCommandClearRules) {
            ClearDynamicRules();
        }
    }
    else {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (ReturnOutputBufferLength) {
        *ReturnOutputBufferLength = 0;
    }

    return STATUS_SUCCESS;
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

    if (!ConnectionPortCookie) {
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS ConnectingProcess = PsGetCurrentProcess();
    ObReferenceObject(ConnectingProcess);
    *ConnectionPortCookie = ConnectingProcess;

    SafeSetPyasPid((ULONG)(ULONG_PTR)PsGetCurrentProcessId());
    InterlockedExchange(&GlobalData.UnloadAuthorized, 0);

    KIRQL OldIrql;
    KeAcquireSpinLock(&GlobalData.PortMutex, &OldIrql);

    GlobalData.ClientPort = ClientPort;
    GlobalData.PyasProcess = ConnectingProcess;
    ExReInitializeRundownProtection(&GlobalData.PortRundown);

    KeReleaseSpinLock(&GlobalData.PortMutex, OldIrql);
    return STATUS_SUCCESS;
}

static VOID PortDisconnect(PVOID ConnectionCookie) {
    KIRQL OldIrql;
    KeAcquireSpinLock(&GlobalData.PortMutex, &OldIrql);

    GlobalData.ClientPort = NULL;
    GlobalData.PyasProcess = NULL;

    KeReleaseSpinLock(&GlobalData.PortMutex, OldIrql);

    InterlockedExchange(&GlobalData.UnloadAuthorized, 0);
    SafeSetPyasPid(0);
    ExWaitForRundownProtectionRelease(&GlobalData.PortRundown);

    if (ConnectionCookie) {
        ObDereferenceObject((PEPROCESS)ConnectionCookie);
    }
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

    InitializeRulesEngine();
    g_RulesEngineInitialized = TRUE;

    NTSTATUS status = LoadRulesFromDisk(RegistryPath);
    if (!NT_SUCCESS(status)) {
        CleanupDriverState();
        return status;
    }

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &GlobalData.FilterHandle);
    if (!NT_SUCCESS(status)) {
        CleanupDriverState();
        return status;
    }

    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
    status = FltBuildDefaultSecurityDescriptor(&SecurityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        CleanupDriverState();
        return status;
    }

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

    status = FltCreateCommunicationPort(
        GlobalData.FilterHandle,
        &GlobalData.ServerPort,
        &ObjectAttributes,
        NULL,
        PortConnect,
        PortDisconnect,
        PortMessage,
        1
    );

    FltFreeSecurityDescriptor(SecurityDescriptor);

    if (!NT_SUCCESS(status)) {
        CleanupDriverState();
        return status;
    }

    status = InitializeRegistryProtection(DriverObject);
    if (!NT_SUCCESS(status)) {
        CleanupDriverState();
        return status;
    }
    g_RegistryProtectionInitialized = TRUE;

    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    if (!NT_SUCCESS(status)) {
        CleanupDriverState();
        return status;
    }
    g_ProcessNotifyRegistered = TRUE;

    status = InitializeMemoryProtection(DriverObject);
    if (!NT_SUCCESS(status)) {
        CleanupDriverState();
        return status;
    }

    status = FltStartFiltering(GlobalData.FilterHandle);
    if (!NT_SUCCESS(status)) {
        CleanupDriverState();
        return status;
    }

    GlobalData.Initialized = TRUE;
    return STATUS_SUCCESS;
}
