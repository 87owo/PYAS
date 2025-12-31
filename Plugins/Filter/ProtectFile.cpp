#include "DriverCommon.h"

static BOOLEAN IsHoneyToken(PUNICODE_STRING Path) {
    if (!Path || !Path->Buffer) return FALSE;
    if (WildcardMatch(L"*PYAS_Honey*", Path->Buffer, Path->Length) ||
        WildcardMatch(L"*Backup_Secret*", Path->Buffer, Path->Length)) {
        return TRUE;
    }
    return FALSE;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    UNICODE_STRING FileName = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FileName = nameInfo->Name;

    if (FileName.Buffer) {
        HANDLE Pid = PsGetCurrentProcessId();
        BOOLEAN Trusted = IsProcessTrusted(Pid);

        if (IsHoneyToken(&FileName)) {
            if (!Trusted) {
                if (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & (FILE_WRITE_DATA | DELETE)) {
                    SendMessageToUser(5001, (ULONG)(ULONG_PTR)Pid, FileName.Buffer);
                    FltReleaseFileNameInformation(nameInfo);
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    return FLT_PREOP_COMPLETE;
                }
            }
        }

        if (WildcardMatch(L"\\Device\\PhysicalDrive*", FileName.Buffer, FileName.Length) ||
            (WildcardMatch(L"\\Device\\Harddisk*", FileName.Buffer, FileName.Length) && !wcsstr(FileName.Buffer, L"Volume"))) {

            if (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &
                (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)) {

                if (!Trusted && !IsInstallerProcess(Pid)) {
                    SendMessageToUser(4001, (ULONG)(ULONG_PTR)Pid, L"Disk_Wiper_Attempt");
                    FltReleaseFileNameInformation(nameInfo);
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    return FLT_PREOP_COMPLETE;
                }
            }
        }

        if (CheckProtectedPathRule(&FileName)) {
            if (!Trusted) {
                if (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & (FILE_WRITE_DATA | DELETE | WRITE_DAC | GENERIC_WRITE)) {
                    SendMessageToUser(2001, (ULONG)(ULONG_PTR)Pid, FileName.Buffer);
                    FltReleaseFileNameInformation(nameInfo);
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    return FLT_PREOP_COMPLETE;
                }
            }
        }

        if (CheckFileExtensionRule(&FileName)) {
            if (!Trusted) {
                if (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & (DELETE | FILE_DELETE_CHILD)) {
                    if (CheckRansomActivity(Pid, &FileName, NULL, 0, FALSE)) {
                        SendMessageToUser(5001, (ULONG)(ULONG_PTR)Pid, FileName.Buffer);
                        FltReleaseFileNameInformation(nameInfo);
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        return FLT_PREOP_COMPLETE;
                    }
                }
            }
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (KeGetCurrentIrql() > APC_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (Data->Iopb->IrpFlags & (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(nameInfo);
        if (NT_SUCCESS(status)) {
            if (CheckFileExtensionRule(&nameInfo->Name)) {
                HANDLE Pid = PsGetCurrentProcessId();
                if (!IsProcessTrusted(Pid)) {

                    PVOID WriteBuffer = NULL;
                    ULONG WriteLength = Data->Iopb->Parameters.Write.Length;

                    if (WriteLength > 0) {
                        if (Data->Iopb->Parameters.Write.MdlAddress) {
                            WriteBuffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress, NormalPagePriority | MdlMappingNoExecute);
                        }
                        else {
                            if (NT_SUCCESS(FltLockUserBuffer(Data))) {
                                if (Data->Iopb->Parameters.Write.MdlAddress) {
                                    WriteBuffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress, NormalPagePriority | MdlMappingNoExecute);
                                }
                            }
                        }
                    }

                    if (WriteBuffer) {
                        if (CheckRansomActivity(Pid, &nameInfo->Name, WriteBuffer, WriteLength, TRUE)) {
                            SendMessageToUser(5001, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer);
                            FltReleaseFileNameInformation(nameInfo);
                            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                            return FLT_PREOP_COMPLETE;
                        }
                    }
                }
            }
        }
        FltReleaseFileNameInformation(nameInfo);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}