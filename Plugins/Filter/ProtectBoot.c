#include <ntifs.h>
#include "DriverEntry.h"
#include "ProtectRules.h"

PDEVICE_OBJECT g_MbrFilterTargets[MAX_MBR_TARGETS] = { 0 };
ULONG g_MbrFilterCount = 0;

NTSTATUS FileProtectDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PDEVICE_OBJECT lower = (PDEVICE_OBJECT)DeviceObject->DeviceExtension;
    if (!lower) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    if (g_Unloading) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(lower, Irp);
    }
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    if (stack->MajorFunction == IRP_MJ_POWER) {
        PoStartNextPowerIrp(Irp);
        IoSkipCurrentIrpStackLocation(Irp);
        return PoCallDriver(lower, Irp);
    }
    HANDLE pid = PsGetCurrentProcessId();
    ULONG currentPid = (ULONG)(ULONG_PTR)pid;
    if (currentPid == 0 || currentPid == 4) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(lower, Irp);
    }
    BOOLEAN blocked = FALSE, is_white = FALSE;
    CHAR logbuf[1024] = { 0 };

    WCHAR exeBuf[512] = { 0 };
    UNICODE_STRING exeName = { 0 };
    exeName.Buffer = exeBuf;
    exeName.MaximumLength = sizeof(exeBuf);
    exeName.Length = 0;

    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        if (GetProcessImagePathByPid(pid, &exeName))
            is_white = IsWhitelist(&exeName);
        else {
            PEPROCESS eproc = PsGetCurrentProcess();
            PCSTR n = PsGetProcessImageFileName(eproc);
            size_t l = n ? strlen(n) : 0;

            for (size_t i = 0; i < l && i < RTL_NUMBER_OF(exeBuf) - 1; i++)
                exeBuf[i] = (WCHAR)n[i];
            exeBuf[l] = 0;
            exeName.Length = (USHORT)(l * sizeof(WCHAR));
        }
    }
    if (!is_white) {
        UCHAR mj = stack->MajorFunction;
        BOOLEAN isDisk = (DeviceObject->DeviceType == FILE_DEVICE_DISK);

        if (!isDisk) {
            PDEVICE_OBJECT tdo = IoGetAttachedDeviceReference(lower);
            if (tdo) {
                isDisk = (tdo->DeviceType == FILE_DEVICE_DISK || tdo->DeviceType == FILE_DEVICE_DISK_FILE_SYSTEM);
                ObDereferenceObject(tdo);
            }
        }
        if (isDisk) {
            if (mj == IRP_MJ_WRITE || mj == IRP_MJ_SET_INFORMATION || mj == IRP_MJ_DEVICE_CONTROL || mj == IRP_MJ_INTERNAL_DEVICE_CONTROL)
                blocked = TRUE;
        }
    }
    if (blocked) {
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            CHAR target[64] = "None";
            ULONG ret = 0;
            POBJECT_NAME_INFORMATION oni = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, 1024, 'nOmD');

            if (oni && NT_SUCCESS(ObQueryNameString(lower, oni, 1024, &ret)) && oni->Name.Buffer && oni->Name.Length >= sizeof(WCHAR) * 2) {
                USHORT len = oni->Name.Length / sizeof(WCHAR);
                ULONG dr = 0;
                BOOLEAN hasDr = FALSE;

                for (USHORT i = 0; i + 2 < len; i++) {
                    if (oni->Name.Buffer[i] == L'D' && oni->Name.Buffer[i + 1] == L'R') {
                        USHORT j = i + 2;
                        ULONG x = 0;

                        while (j < len && oni->Name.Buffer[j] >= L'0' && oni->Name.Buffer[j] <= L'9') {
                            x = x * 10 + (oni->Name.Buffer[j] - L'0');
                            j++;
                        }
                        dr = x;
                        hasDr = TRUE;
                        break;
                    }
                }
                if (hasDr)
                    RtlStringCchPrintfA(target, sizeof(target), "Disk\\Device\\DR%u", dr);
            }
            if (oni)
                ExFreePool(oni);
            RtlStringCchPrintfA(logbuf, sizeof(logbuf), "BOOT_BLOCK | %u | %wZ | %s", currentPid, &exeName, target);
            SendPipeLog(logbuf, strlen(logbuf));
            ZwTerminateProcess(NtCurrentProcess(), STATUS_ACCESS_DENIED);
        }
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(lower, Irp);
}
