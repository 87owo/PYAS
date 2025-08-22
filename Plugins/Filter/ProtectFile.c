#include <ntifs.h>
#include "DriverEntry.h"
#include "ProtectMatch.h"

static BOOLEAN GetFilePathFromFileObject(PFILE_OBJECT fo, PUNICODE_STRING out)
{
    if (!fo || !out || !out->Buffer || out->MaximumLength == 0)
        return FALSE;

    out->Length = 0;
    if (fo->DeviceObject && fo->FileName.Buffer && fo->FileName.Length) {
        ULONG need = 0;
        NTSTATUS s = ObQueryNameString(fo->DeviceObject, NULL, 0, &need);
        if (s == STATUS_INFO_LENGTH_MISMATCH && need > 0) {
            POBJECT_NAME_INFORMATION oni = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, need, 'nOmD');
            if (oni) {
                if (NT_SUCCESS(ObQueryNameString(fo->DeviceObject, oni, need, &need)) && oni->Name.Buffer && oni->Name.Length) {
                    ULONG total = oni->Name.Length + fo->FileName.Length;
                    if (total + sizeof(WCHAR) <= out->MaximumLength) {
                        RtlCopyMemory(out->Buffer, oni->Name.Buffer, oni->Name.Length);
                        RtlCopyMemory((PUCHAR)out->Buffer + oni->Name.Length, fo->FileName.Buffer, fo->FileName.Length);
                        out->Length = (USHORT)total;
                        out->Buffer[total / sizeof(WCHAR)] = 0;
                        ExFreePool2(oni, 'nOmD', NULL, 0);
                        return TRUE;
                    }
                }
                ExFreePool2(oni, 'nOmD', NULL, 0);
            }
        }
    }
    HANDLE hFile = NULL;
    OBJECT_ATTRIBUTES oa = { 0 };
    IO_STATUS_BLOCK iosb;
    
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ObOpenObjectByPointer(fo, OBJ_KERNEL_HANDLE, NULL, FILE_READ_ATTRIBUTES, *IoFileObjectType, KernelMode, &hFile)))
        return FALSE;
    
    ULONG buflen = sizeof(FILE_NAME_INFORMATION) + 2048 * sizeof(WCHAR);
    PFILE_NAME_INFORMATION pfi = (PFILE_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, buflen, 'nIIF');
    if (!pfi) {
        ZwClose(hFile);
        return FALSE;
    }
    RtlZeroMemory(pfi, buflen);
    NTSTATUS st = ZwQueryInformationFile(hFile, &iosb, pfi, buflen, FileNormalizedNameInformation);
    
    if (NT_SUCCESS(st) && pfi->FileNameLength > 0 && pfi->FileNameLength + sizeof(WCHAR) <= out->MaximumLength) {
        RtlCopyMemory(out->Buffer, pfi->FileName, pfi->FileNameLength);
        out->Length = (USHORT)pfi->FileNameLength;
        out->Buffer[out->Length / sizeof(WCHAR)] = 0;
        ExFreePool2(pfi, 'nIIF', NULL, 0);
        ZwClose(hFile);
        return TRUE;
    }
    ExFreePool2(pfi, 'nIIF', NULL, 0);
    ZwClose(hFile);
    return FALSE;
}

static BOOLEAN WantDelete(PIRP Irp, PIO_STACK_LOCATION s)
{
    if (s->MajorFunction != IRP_MJ_SET_INFORMATION)
        return FALSE;
    
    FILE_INFORMATION_CLASS c = s->Parameters.SetFile.FileInformationClass;
    if (c == FileDispositionInformation) {
        PFILE_DISPOSITION_INFORMATION di = (PFILE_DISPOSITION_INFORMATION)Irp->AssociatedIrp.SystemBuffer;
        return di && di->DeleteFile;
    }
    if (c == FileDispositionInformationEx) {
        PFILE_DISPOSITION_INFORMATION_EX dx = (PFILE_DISPOSITION_INFORMATION_EX)Irp->AssociatedIrp.SystemBuffer;
        return dx && (dx->Flags & FILE_DISPOSITION_DELETE);
    }
    return FALSE;
}

static BOOLEAN WantRename(PIRP Irp, PIO_STACK_LOCATION s)
{
    if (s->MajorFunction != IRP_MJ_SET_INFORMATION)
        return FALSE;
    
    FILE_INFORMATION_CLASS c = s->Parameters.SetFile.FileInformationClass;
    if (c == FileRenameInformation || c == FileRenameInformationEx)
        return Irp->AssociatedIrp.SystemBuffer != NULL;
    return FALSE;
}

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

static VOID LogAnsi3(PCSTR tag, ULONG upid, PUNICODE_STRING s1, PUNICODE_STRING s2)
{
    ANSI_STRING a1 = { 0 }, a2 = { 0 };
    CHAR buf[1024] = { 0 };
    RtlUnicodeStringToAnsiString(&a1, s1, TRUE);
    if (s2)
        RtlUnicodeStringToAnsiString(&a2, s2, TRUE);
    RtlStringCchPrintfA(buf, RTL_NUMBER_OF(buf), "%s | %u | %s | %s", tag, upid, a1.Buffer ? a1.Buffer : "", a2.Buffer ? a2.Buffer : "");
    SendPipeLog(buf, strlen(buf));
    RtlFreeAnsiString(&a1);
    RtlFreeAnsiString(&a2);
}

static BOOLEAN QueryDevName(PDEVICE_OBJECT dev, PUNICODE_STRING out)
{
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

static BOOLEAN IsDASDRoot(PFILE_OBJECT fo)
{
    if (!fo)
        return TRUE;
    if (fo->FileName.Length == 0 && fo->RelatedFileObject == NULL)
        return TRUE;
    return FALSE;
}

static BOOLEAN IsDangerousDiskIo(PIO_STACK_LOCATION s)
{
    if (!s)
        return FALSE;
    if (s->MajorFunction == IRP_MJ_DEVICE_CONTROL || s->MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL) {
        ULONG code = s->Parameters.DeviceIoControl.IoControlCode;
        if (code == IOCTL_SCSI_PASS_THROUGH || code == IOCTL_SCSI_PASS_THROUGH_DIRECT)
            return TRUE;
        if (code == IOCTL_DISK_SET_DRIVE_LAYOUT || code == IOCTL_DISK_SET_DRIVE_LAYOUT_EX)
            return TRUE;
        if (code == IOCTL_DISK_DELETE_DRIVE_LAYOUT)
            return TRUE;
        if (code == IOCTL_DISK_FORMAT_TRACKS || code == IOCTL_DISK_FORMAT_TRACKS_EX)
            return TRUE;
        if (code == IOCTL_DISK_SET_PARTITION_INFO || code == IOCTL_DISK_SET_PARTITION_INFO_EX)
            return TRUE;
        return FALSE;
    }
    if (s->MajorFunction == IRP_MJ_SCSI)
        return TRUE;
    if (s->MajorFunction == IRP_MJ_WRITE || s->MajorFunction == IRP_MJ_FLUSH_BUFFERS)
        return TRUE;
    return FALSE;
}

NTSTATUS FileProtectDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
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
    BOOLEAN isWrite = (s->MajorFunction == IRP_MJ_WRITE);
    BOOLEAN isDeleteReq = WantDelete(Irp, s);
    BOOLEAN isRenameReq = WantRename(Irp, s);
    BOOLEAN canQuery = (KeGetCurrentIrql() == PASSIVE_LEVEL);

    WCHAR eb[512] = { 0 };
    UNICODE_STRING exe = { 0 };
    exe.Buffer = eb;
    exe.MaximumLength = sizeof(eb);

    if (canQuery) {
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
            BOOLEAN hit = FALSE;
            WCHAR db[512] = { 0 };
            UNICODE_STRING dev = { 0 };
            dev.Buffer = db;
            dev.MaximumLength = sizeof(db);
            
            if (canQuery && QueryDevName(lower, &dev)) {
                if (MatchBlockFile(&dev))
                    hit = TRUE;
            }
            else {
                hit = TRUE;
            }
            if (!hit && s->FileObject && canQuery) {
                WCHAR nb[512] = { 0 };
                UNICODE_STRING n2 = { 0 };
                n2.Buffer = nb;
                n2.MaximumLength = sizeof(nb);
                
                if (QueryDevName(s->FileObject->DeviceObject, &n2)) {
                    if (MatchBlockFile(&n2))
                        hit = TRUE;
                }
            }
            if (!hit && s->MajorFunction == IRP_MJ_WRITE && s->FileObject && IsDASDRoot(s->FileObject))
                hit = TRUE;
            if (hit) {
                blocked = TRUE;
                if (canQuery) {
                    if (dev.Length == 0)
                        QueryDevName(lower, &dev);
                    LogAnsi3("BOOT_BLOCK", upid, &exe, dev.Length ? &dev : &exe);
                }
            }
        }
    }
    if (!blocked && (isWrite || isDeleteReq || isRenameReq) && s->FileObject && canQuery) {
        WCHAR pb[1024] = { 0 };
        UNICODE_STRING path = { 0 };
        path.Buffer = pb;
        path.MaximumLength = sizeof(pb);
        
        if (GetFilePathFromFileObject(s->FileObject, &path)) {
            BOOLEAN hitFile = MatchBlockFile(&path);
            BOOLEAN hitRansom = MatchBlockRansom(&path) && HasBlockedSuffix(&path);
            if (hitFile || hitRansom) {
                blocked = TRUE;
                LogAnsi3(hitFile && !hitRansom ? "FILE_BLOCK" : "RANSOM_BLOCK", upid, &exe, &path);
            }
        }
        else {
            ULONG need = 0;
            POBJECT_NAME_INFORMATION dev = NULL;
            NTSTATUS qs2 = ObQueryNameString(s->FileObject->DeviceObject, NULL, 0, &need);
            
            if (qs2 == STATUS_INFO_LENGTH_MISMATCH && need > 0) {
                dev = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, need, 'dOnF');
                if (dev && NT_SUCCESS(ObQueryNameString(s->FileObject->DeviceObject, dev, need, &need)) && dev->Name.Buffer && dev->Name.Length) {
                    if (MatchBlockFile(&dev->Name)) {
                        blocked = TRUE;
                        UNICODE_STRING rule = { 0 };
                        rule.Buffer = GetMatchedBlockFileRule(&dev->Name);
                        rule.Length = rule.Buffer ? (USHORT)(wcslen(rule.Buffer) * sizeof(WCHAR)) : 0;
                        rule.MaximumLength = rule.Length;
                        LogAnsi3("FILE_BLOCK", upid, &exe, rule.Buffer ? &rule : &dev->Name);
                    }
                }
                if (dev)
                    ExFreePool2(dev, 'dOnF', NULL, 0);
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
