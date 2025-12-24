#include <ntifs.h>
#include "DriverEntry.h"
#include "ProtectRules.h"

LARGE_INTEGER g_CmRegHandle;
PDEVICE_OBJECT g_ControlDeviceObject;
KSPIN_LOCK g_ProtectLock;
FAST_MUTEX HookMutex;
PDRIVER_OBJECT DiskDrvObj = NULL;
KEVENT g_LogDrainEvent;
BOOLEAN g_Unloading = FALSE;
BOOLEAN g_CmRegActive = FALSE;
EX_RUNDOWN_REF g_Rundown;
PDEVICE_OBJECT g_GuardDevice = NULL;
PDRIVER_OBJECT g_DriverObject = NULL;

PDEVICE_OBJECT g_MbrFilterTargets[MAX_MBR_TARGETS] = { 0 };
ULONG g_MbrFilterCount = 0;

volatile LONG g_LogWorkCount = 0;
static UNICODE_STRING g_DeviceName;
static WCHAR g_DeviceNameBuf[64];
static UNICODE_STRING g_SymLink = RTL_CONSTANT_STRING(L"\\??\\PYAS_Driver");
static BOOLEAN g_SymLinkCreated = FALSE;

static NTSTATUS CombinedDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (DeviceObject == g_ControlDeviceObject) {
        PIO_STACK_LOCATION s = IoGetCurrentIrpStackLocation(Irp);
        if (s->MajorFunction == IRP_MJ_CREATE || s->MajorFunction == IRP_MJ_CLOSE || s->MajorFunction == IRP_MJ_CLEANUP) {
            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    PIO_STACK_LOCATION s = IoGetCurrentIrpStackLocation(Irp);
    if (s->MajorFunction == IRP_MJ_PNP) {
        PDEVICE_OBJECT lower = (PDEVICE_OBJECT)DeviceObject->DeviceExtension;
        if (s->MinorFunction == IRP_MN_REMOVE_DEVICE) {
            NTSTATUS st;
            IoSkipCurrentIrpStackLocation(Irp);
            st = lower ? IoCallDriver(lower, Irp) : STATUS_SUCCESS;
            if (lower) IoDetachDevice(lower);
            IoDeleteDevice(DeviceObject);
            return st;
        }
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver((PDEVICE_OBJECT)DeviceObject->DeviceExtension, Irp);
    }

    return BootProtectDispatch(DeviceObject, Irp);
}

static NTSTATUS AttachDiskFilters(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
    UNICODE_STRING sym = RTL_CONSTANT_STRING(L"IoDriverObjectType");
    POBJECT_TYPE* pType = (POBJECT_TYPE*)MmGetSystemRoutineAddress(&sym);

    if (!pType || !*pType)
        return STATUS_NOT_SUPPORTED;

    NTSTATUS status = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE, NULL, 0, *pType, KernelMode, NULL, (PVOID*)&DiskDrvObj);
    if (!NT_SUCCESS(status))
        return status;

    ULONG done = 0;
    status = IoEnumerateDeviceObjectList(DiskDrvObj, NULL, 0, &done);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_SUCCESS) {
        ObDereferenceObject(DiskDrvObj);
        DiskDrvObj = NULL;
        return status;
    }

    PDEVICE_OBJECT* list = ExAllocatePool2(POOL_FLAG_NON_PAGED, done * sizeof(PDEVICE_OBJECT), 'dskT');
    if (!list) {
        ObDereferenceObject(DiskDrvObj);
        DiskDrvObj = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoEnumerateDeviceObjectList(DiskDrvObj, list, done * sizeof(PDEVICE_OBJECT), &done);
    if (!NT_SUCCESS(status)) {
        ExFreePool2(list, 'dskT', NULL, 0);
        ObDereferenceObject(DiskDrvObj);
        DiskDrvObj = NULL;
        return status;
    }

    for (ULONG i = 0; i < done && g_MbrFilterCount < MAX_MBR_TARGETS; ++i) {
        PDEVICE_OBJECT lower = list[i], filter, attached = NULL;

        status = IoCreateDevice(DriverObject, 0, NULL, lower->DeviceType, lower->Characteristics, FALSE, &filter);
        if (!NT_SUCCESS(status))
            continue;

        filter->Flags |= (lower->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE));

        status = IoAttachDeviceToDeviceStackSafe(filter, lower, &attached);
        if (!NT_SUCCESS(status) || !attached) {
            IoDeleteDevice(filter);
            continue;
        }

        filter->StackSize = lower->StackSize + 1;
        filter->AlignmentRequirement = lower->AlignmentRequirement;
        filter->DeviceExtension = attached;
        filter->Flags &= ~DO_DEVICE_INITIALIZING;
        g_MbrFilterTargets[g_MbrFilterCount++] = filter;
    }

    for (ULONG i = 0; i < done; ++i)
        ObDereferenceObject(list[i]);
    ExFreePool2(list, 'dskT', NULL, 0);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    g_DriverObject = DriverObject;

    KeInitializeSpinLock(&g_ProtectLock);
    ExInitializeFastMutex(&HookMutex);
    KeInitializeEvent(&g_LogDrainEvent, NotificationEvent, TRUE);
    g_Unloading = FALSE;
    g_CmRegActive = FALSE;

    InterlockedExchange(&g_LogWorkCount, 0);
    ExInitializeRundownProtection(&g_Rundown);

    {
        UNICODE_STRING guardName = RTL_CONSTANT_STRING(L"\\Device\\PYAS_Driver_Guard");
        NTSTATUS gs = IoCreateDevice(DriverObject, 0, &guardName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_GuardDevice);
        if (!NT_SUCCESS(gs))
            return STATUS_DEVICE_BUSY;
    }

    {
        LARGE_INTEGER t = KeQueryPerformanceCounter(NULL);
        g_DeviceName.Buffer = g_DeviceNameBuf;
        g_DeviceName.MaximumLength = sizeof(g_DeviceNameBuf);
        RtlStringCchPrintfW(g_DeviceName.Buffer, RTL_NUMBER_OF(g_DeviceNameBuf), L"\\Device\\PYAS_Driver_%p_%I64x", DriverObject, t.QuadPart);
        g_DeviceName.Length = (USHORT)(wcslen(g_DeviceName.Buffer) * sizeof(WCHAR));
    }

    NTSTATUS status = IoCreateDevice(DriverObject, 0, &g_DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_ControlDeviceObject);
    if (!NT_SUCCESS(status))
        return status;

    DriverObject->DriverUnload = DriverUnload;
    for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
        DriverObject->MajorFunction[i] = CombinedDispatch;

    DriverObject->Flags |= 0x20;
    g_ControlDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    IoDeleteSymbolicLink(&g_SymLink);
    {
        UINT i = 0;
        for (; i < 50; ++i) {
            status = IoCreateSymbolicLink(&g_SymLink, &g_DeviceName);
            if (NT_SUCCESS(status))
                break;
            LARGE_INTEGER d = { 0 };
            d.QuadPart = -10LL * 1000LL * 10LL;
            KeDelayExecutionThread(KernelMode, FALSE, &d);
            IoDeleteSymbolicLink(&g_SymLink);
        }
        if (!NT_SUCCESS(status)) {
            IoDeleteDevice(g_ControlDeviceObject);
            g_ControlDeviceObject = NULL;
            if (g_GuardDevice) { IoDeleteDevice(g_GuardDevice); g_GuardDevice = NULL; }
            return status;
        }
    }
    g_SymLinkCreated = TRUE;

    {
        static WCHAR regAltBuf[32];
        static UNICODE_STRING regAlt;
        LARGE_INTEGER t = KeQueryPerformanceCounter(NULL);
        RtlStringCchPrintfW(regAltBuf, RTL_NUMBER_OF(regAltBuf), L"385100.%I64x", t.QuadPart);
        RtlInitUnicodeString(&regAlt, regAltBuf);

        status = CmRegisterCallbackEx(RegistryProtectCallback, &regAlt, DriverObject, NULL, &g_CmRegHandle, NULL);
        if (NT_SUCCESS(status))
            g_CmRegActive = TRUE;
    }

    InitImageProtect();
    InitInjectProtect();
    InitRemoteProtect();
    InitScreenProtect();
    InitProcessProtect();

    InitFileProtect();
    AttachDiskFilters(DriverObject);

    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    g_Unloading = TRUE;

    if (g_SymLinkCreated) {
        IoDeleteSymbolicLink(&g_SymLink);
        g_SymLinkCreated = FALSE;
    }

    if (g_CmRegActive) {
        CmUnRegisterCallback(g_CmRegHandle);
        g_CmRegActive = FALSE;
    }

    UninitFileProtect();
    UninitInjectProtect();
    UninitImageProtect();
    UninitRemoteProtect();
    UninitScreenProtect();
    UninitProcessProtect();

    ExWaitForRundownProtectionRelease(&g_Rundown);

    if (InterlockedCompareExchange((volatile LONG*)&g_LogWorkCount, 0, 0) != 0) {
        KeWaitForSingleObject(&g_LogDrainEvent, Executive, KernelMode, FALSE, NULL);
    }
    if (InterlockedCompareExchange(&g_LogWorkCount, 0, 0) != 0) {
        KeResetEvent(&g_LogDrainEvent);
        while (InterlockedCompareExchange(&g_LogWorkCount, 0, 0) != 0)
            KeWaitForSingleObject(&g_LogDrainEvent, Executive, KernelMode, FALSE, NULL);
    }

    for (ULONG i = 0; i < g_MbrFilterCount; ++i) {
        if (g_MbrFilterTargets[i]) {
            IoDetachDevice((PDEVICE_OBJECT)g_MbrFilterTargets[i]->DeviceExtension);
            IoDeleteDevice(g_MbrFilterTargets[i]);
            g_MbrFilterTargets[i] = NULL;
        }
    }
    g_MbrFilterCount = 0;

    if (DiskDrvObj) {
        ObDereferenceObject(DiskDrvObj);
        DiskDrvObj = NULL;
    }
    if (g_ControlDeviceObject) {
        IoDeleteDevice(g_ControlDeviceObject);
        g_ControlDeviceObject = NULL;
    }
    if (g_GuardDevice) {
        IoDeleteDevice(g_GuardDevice);
        g_GuardDevice = NULL;
    }
}