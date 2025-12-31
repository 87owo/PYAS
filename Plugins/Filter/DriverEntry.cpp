#include "DriverCommon.h"

DRIVER_DATA GlobalData;

static NTSTATUS InstanceSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

static NTSTATUS InstanceQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

static VOID InstanceTeardownStart(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

static VOID InstanceTeardownComplete(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

static NTSTATUS DriverUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);

    PsRemoveLoadImageNotifyRoutine(ImageLoadNotify);
    UninitializeRegistryProtection();
    UninitializeProcessProtection();

    if (GlobalData.ServerPort) {
        FltCloseCommunicationPort(GlobalData.ServerPort);
    }
    if (GlobalData.FilterHandle) {
        FltUnregisterFilter(GlobalData.FilterHandle);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS PortConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID* ConnectionPortCookie) {
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);

    ExAcquireFastMutex(&GlobalData.PortMutex);
    GlobalData.ClientPort = ClientPort;
    GlobalData.PyasPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    GlobalData.PyasProcess = PsGetCurrentProcess();
    ExReleaseFastMutex(&GlobalData.PortMutex);

    return STATUS_SUCCESS;
}

static VOID PortDisconnect(PVOID ConnectionCookie) {
    UNREFERENCED_PARAMETER(ConnectionCookie);

    ExAcquireFastMutex(&GlobalData.PortMutex);
    GlobalData.ClientPort = NULL;
    GlobalData.PyasPid = 0;
    if (GlobalData.PyasProcess) {
        GlobalData.PyasProcess = NULL;
    }
    ExReleaseFastMutex(&GlobalData.PortMutex);
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, ProtectFile_PreCreate, NULL },
    { IRP_MJ_WRITE, 0, ProtectFile_PreWrite, NULL },
    { IRP_MJ_SET_INFORMATION, 0, ProtectFile_PreWrite, NULL },
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

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_SUCCESS;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa = { 0 };
    UNICODE_STRING name = { 0 };

    RtlZeroMemory(&GlobalData, sizeof(GlobalData));
    GlobalData.DriverObject = DriverObject;
    ExInitializeFastMutex(&GlobalData.PortMutex);
    ExInitializeFastMutex(&GlobalData.TrackerMutex);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &GlobalData.FilterHandle);
    if (!NT_SUCCESS(status)) return status;

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&name, PYAS_PORT_NAME);
        InitializeObjectAttributes(&oa, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
        status = FltCreateCommunicationPort(GlobalData.FilterHandle, &GlobalData.ServerPort, &oa, NULL, PortConnect, PortDisconnect, NULL, 1);
        FltFreeSecurityDescriptor(sd);
    }

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(GlobalData.FilterHandle);
        return status;
    }

    InitializeProcessProtection();
    InitializeRegistryProtection(DriverObject);
    PsSetLoadImageNotifyRoutine(ImageLoadNotify);

    return FltStartFiltering(GlobalData.FilterHandle);
}