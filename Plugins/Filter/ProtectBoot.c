#include <ntifs.h>
#include "DriverEntry.h"
#include "ProtectMatch.h"

#define PROTECTED_BOOT_AREA_SIZE (34 * 512)

static VOID GetExeNameForLog(HANDLE pid, PUNICODE_STRING exe)
{
    if (!exe || !exe->Buffer || exe->MaximumLength == 0)
        return;

    exe->Length = 0;
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        if (GetProcessImagePathByPid(pid, exe))
            return;
    }
    PEPROCESS eproc = PsGetCurrentProcess();
    PCSTR n = PsGetProcessImageFileName(eproc);
    size_t l = n ? strlen(n) : 0;

    for (size_t i = 0; i < l && i < (exe->MaximumLength / sizeof(WCHAR)) - 1; i++)
        exe->Buffer[i] = (WCHAR)n[i];
    exe->Buffer[l] = 0;
    exe->Length = (USHORT)(l * sizeof(WCHAR));
}

static BOOLEAN QueryDevName(PDEVICE_OBJECT dev, PUNICODE_STRING out)
{
    if (KeGetCurrentIrql() > APC_LEVEL)
        return FALSE;

    if (!dev || !out || !out->Buffer || out->MaximumLength == 0)
        return FALSE;

    ULONG need = 0;
    NTSTATUS s = ObQueryNameString(dev, NULL, 0, &need);
    if (s != STATUS_INFO_LENGTH_MISMATCH || need == 0)
        return FALSE;

    POBJECT_NAME_INFORMATION oni = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, need, 'nOmD');
    if (!oni)
        return FALSE;

    BOOLEAN ok = FALSE;
    s = ObQueryNameString(dev, oni, need, &need);
    if (NT_SUCCESS(s) && oni->Name.Buffer && oni->Name.Length && oni->Name.Length < out->MaximumLength) {
        RtlCopyMemory(out->Buffer, oni->Name.Buffer, oni->Name.Length);
        out->Length = (USHORT)oni->Name.Length;
        out->Buffer[out->Length / sizeof(WCHAR)] = 0;
        ok = TRUE;
    }
    ExFreePool2(oni, 'nOmD', NULL, 0);
    return ok;
}

static BOOLEAN IsDangerousDiskIo(PIO_STACK_LOCATION s)
{
    if (!s) return FALSE;

    if (s->MajorFunction == IRP_MJ_DEVICE_CONTROL || s->MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL) {
        ULONG code = s->Parameters.DeviceIoControl.IoControlCode;
        if (code == IOCTL_DISK_SET_DRIVE_LAYOUT || code == IOCTL_DISK_SET_DRIVE_LAYOUT_EX) return TRUE;
        if (code == IOCTL_DISK_DELETE_DRIVE_LAYOUT) return TRUE;
        if (code == IOCTL_DISK_FORMAT_TRACKS || code == IOCTL_DISK_FORMAT_TRACKS_EX) return TRUE;
        if (code == IOCTL_DISK_SET_PARTITION_INFO || code == IOCTL_DISK_SET_PARTITION_INFO_EX) return TRUE;
        if (code == IOCTL_SCSI_PASS_THROUGH || code == IOCTL_SCSI_PASS_THROUGH_DIRECT) return TRUE;
    }

    return FALSE;
}

static BOOLEAN IsBootSectorWrite(PIO_STACK_LOCATION s)
{
    if (s->MajorFunction == IRP_MJ_WRITE) {
        LARGE_INTEGER offset = s->Parameters.Write.ByteOffset;
        if (offset.QuadPart < PROTECTED_BOOT_AREA_SIZE) {
            return TRUE;
        }
    }
    return FALSE;
}

NTSTATUS BootProtectDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PDEVICE_OBJECT lower = (PDEVICE_OBJECT)DeviceObject->DeviceExtension;
    if (!lower) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (!ExAcquireRundownProtection(&g_Rundown)) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(lower, Irp);
    }

    if (g_Unloading) {
        IoSkipCurrentIrpStackLocation(Irp);
        NTSTATUS rs = IoCallDriver(lower, Irp);
        ExReleaseRundownProtection(&g_Rundown);
        return rs;
    }

    PIO_STACK_LOCATION s = IoGetCurrentIrpStackLocation(Irp);

    if (s->MajorFunction == IRP_MJ_POWER) {
        PoStartNextPowerIrp(Irp);
        IoSkipCurrentIrpStackLocation(Irp);
        NTSTATUS ps = PoCallDriver(lower, Irp);
        ExReleaseRundownProtection(&g_Rundown);
        return ps;
    }

    HANDLE pid = PsGetCurrentProcessId();
    ULONG upid = (ULONG)(ULONG_PTR)pid;

    if (upid == 0 || upid == 4) {
        IoSkipCurrentIrpStackLocation(Irp);
        NTSTATUS ns = IoCallDriver(lower, Irp);
        ExReleaseRundownProtection(&g_Rundown);
        return ns;
    }

    BOOLEAN blocked = FALSE;
    WCHAR eb[512] = { 0 };
    UNICODE_STRING exe = { 0 };
    exe.Buffer = eb;
    exe.MaximumLength = sizeof(eb);

    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        GetExeNameForLog(pid, &exe);
        if (IsWhitelist(&exe)) {
            IoSkipCurrentIrpStackLocation(Irp);
            NTSTATUS ns2 = IoCallDriver(lower, Irp);
            ExReleaseRundownProtection(&g_Rundown);
            return ns2;
        }
    }

    if (lower->DeviceType == FILE_DEVICE_DISK) {
        if (IsDangerousDiskIo(s)) {
            blocked = TRUE;
        }

        if (!blocked && IsBootSectorWrite(s)) {
            blocked = TRUE;
        }

        if (blocked) {
            if (KeGetCurrentIrql() <= APC_LEVEL) {
                WCHAR db[512] = { 0 };
                UNICODE_STRING dev = { 0 };
                dev.Buffer = db;
                dev.MaximumLength = sizeof(db);
                QueryDevName(lower, &dev);

                LogAnsi3("BOOT_BLOCK", upid, &exe, dev.Length ? &dev : &exe);
            }
        }
    }

    if (blocked) {
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        ExReleaseRundownProtection(&g_Rundown);
        return STATUS_ACCESS_DENIED;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    NTSTATUS rs2 = IoCallDriver(lower, Irp);
    ExReleaseRundownProtection(&g_Rundown);
    return rs2;
}