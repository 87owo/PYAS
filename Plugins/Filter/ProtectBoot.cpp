#include "DriverCommon.h"

#ifndef IOCTL_DISK_FORMAT_TRACKS
#define IOCTL_DISK_FORMAT_TRACKS        CTL_CODE(IOCTL_DISK_BASE, 0x0006, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif
#ifndef IOCTL_DISK_FORMAT_TRACKS_EX
#define IOCTL_DISK_FORMAT_TRACKS_EX     CTL_CODE(IOCTL_DISK_BASE, 0x000b, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

FLT_PREOP_CALLBACK_STATUS ProtectBoot_PreDeviceControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    ULONG IoControlCode = Data->Iopb->Parameters.DeviceIoControl.Common.IoControlCode;

    if (IoControlCode == IOCTL_DISK_SET_DRIVE_LAYOUT_EX ||
        IoControlCode == IOCTL_SCSI_PASS_THROUGH_DIRECT ||
        IoControlCode == IOCTL_DISK_FORMAT_TRACKS ||
        IoControlCode == IOCTL_DISK_FORMAT_TRACKS_EX) {

        HANDLE Pid = PsGetCurrentProcessId();
        if (!IsProcessTrusted(Pid) && !IsInstallerProcess(Pid)) {
            SendMessageToUser(4001, (ULONG)(ULONG_PTR)Pid, L"Disk_Wiper_Attempt");
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            return FLT_PREOP_COMPLETE;
        }
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}