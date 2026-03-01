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
    if (KeGetCurrentIrql() > APC_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    UNICODE_STRING FileName = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FileName = nameInfo->Name;
    if (!FileName.Buffer || FileName.Length == 0) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    HANDLE Pid = PsGetCurrentProcessId();
    BOOLEAN Trusted = IsProcessTrusted(Pid);

    ULONG CreateDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
    BOOLEAN IsCreateAction = (CreateDisposition == FILE_CREATE ||
        CreateDisposition == FILE_SUPERSEDE ||
        CreateDisposition == FILE_OVERWRITE ||
        CreateDisposition == FILE_OVERWRITE_IF ||
        CreateDisposition == FILE_OPEN_IF);

    if (IsHoneyToken(&FileName)) {
        if (!Trusted) {
            if ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & (FILE_WRITE_DATA | DELETE)) || IsCreateAction) {
                SendMessageToUser(5001, (ULONG)(ULONG_PTR)Pid, FileName.Buffer, FileName.Length);
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                callbackStatus = FLT_PREOP_COMPLETE;
                goto cleanup;
            }
        }
    }

    if (WildcardMatch(L"\\Device\\PhysicalDrive*", FileName.Buffer, FileName.Length) ||
        (WildcardMatch(L"\\Device\\Harddisk*", FileName.Buffer, FileName.Length) && !WildcardMatch(L"*Volume*", FileName.Buffer, FileName.Length))) {

        if (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &
            (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)) {

            if (!Trusted) {
                UNICODE_STRING MsgStr = RTL_CONSTANT_STRING(L"Disk_Wiper_Attempt");
                SendMessageToUser(4001, (ULONG)(ULONG_PTR)Pid, MsgStr.Buffer, MsgStr.Length);
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                callbackStatus = FLT_PREOP_COMPLETE;
                goto cleanup;
            }
        }
    }

    if (CheckProtectedPathRule(&FileName)) {
        if (!Trusted) {
            if ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &
                (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | GENERIC_WRITE)) || IsCreateAction) {
                SendMessageToUser(2001, (ULONG)(ULONG_PTR)Pid, FileName.Buffer, FileName.Length);
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                callbackStatus = FLT_PREOP_COMPLETE;
                goto cleanup;
            }
        }
    }

    if (CheckFileExtensionRule(&FileName)) {
        if (!Trusted) {
            if (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & (DELETE | FILE_DELETE_CHILD)) {
                if (CheckRansomActivity(Pid, &FileName, NULL, 0, FALSE)) {
                    SendMessageToUser(5001, (ULONG)(ULONG_PTR)Pid, FileName.Buffer, FileName.Length);
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    callbackStatus = FLT_PREOP_COMPLETE;
                    goto cleanup;
                }
            }
        }
    }

cleanup:
    if (nameInfo) {
        FltReleaseFileNameInformation(nameInfo);
    }
    return callbackStatus;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() > APC_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (infoClass != FileDispositionInformation &&
        infoClass != FileRenameInformation &&
        infoClass != FileRenameInformationEx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

    if (!NT_SUCCESS(status) || !nameInfo) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo->Name.Buffer) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    HANDLE Pid = PsGetCurrentProcessId();
    if (!IsProcessTrusted(Pid)) {

        if (CheckProtectedPathRule(&nameInfo->Name)) {
            SendMessageToUser(2001, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_COMPLETE;
        }

        if (CheckFileExtensionRule(&nameInfo->Name)) {
            if (CheckRansomActivity(Pid, &nameInfo->Name, NULL, 0, FALSE)) {
                SendMessageToUser(5001, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length);
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                FltReleaseFileNameInformation(nameInfo);
                return FLT_PREOP_COMPLETE;
            }
        }
    }
    if (nameInfo) {
        FltReleaseFileNameInformation(nameInfo);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_SetSecurity(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() > APC_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

    if (!NT_SUCCESS(status) || !nameInfo) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo->Name.Buffer) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    SECURITY_INFORMATION SecurityInfo = Data->Iopb->Parameters.SetSecurity.SecurityInformation;

    if (SecurityInfo & (OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION)) {
        if (CheckProtectedPathRule(&nameInfo->Name)) {
            HANDLE Pid = PsGetCurrentProcessId();
            if (!IsProcessTrusted(Pid)) {
                SendMessageToUser(2001, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length);
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                FltReleaseFileNameInformation(nameInfo);
                return FLT_PREOP_COMPLETE;
            }
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (Data->Iopb->IrpFlags & (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_NOCACHE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG WriteLength = Data->Iopb->Parameters.Write.Length;
    if (WriteLength == 0) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

    FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (NT_SUCCESS(status) && nameInfo) {
        status = FltParseFileNameInformation(nameInfo);
        if (NT_SUCCESS(status) && nameInfo->Name.Buffer) {

            if (CheckFileExtensionRule(&nameInfo->Name)) {
                HANDLE Pid = PsGetCurrentProcessId();

                if (!IsProcessTrusted(Pid)) {
                    PVOID SystemBuffer = NULL;
                    PMDL Mdl = Data->Iopb->Parameters.Write.MdlAddress;

                    if (!Mdl) {
                        if (Data->Iopb->Parameters.Write.WriteBuffer && KeGetCurrentIrql() <= APC_LEVEL) {
                            if (NT_SUCCESS(FltLockUserBuffer(Data))) {
                                Mdl = Data->Iopb->Parameters.Write.MdlAddress;
                            }
                        }
                    }

                    if (Mdl) {
                        SystemBuffer = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority | MdlMappingNoExecute);
                    }

                    if (SystemBuffer) {
                        if (CheckRansomActivity(Pid, &nameInfo->Name, SystemBuffer, WriteLength, TRUE)) {
                            SendMessageToUser(5001, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length);
                            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                            callbackStatus = FLT_PREOP_COMPLETE;
                        }
                    }
                }
            }
        }
        FltReleaseFileNameInformation(nameInfo);
    }
    return callbackStatus;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_FileSystemControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode != FSCTL_MANAGE_BYPASS_IO) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFS_BPIO_INPUT InputBuffer = (PFS_BPIO_INPUT)Data->Iopb->Parameters.FileSystemControl.Neither.InputBuffer;
    if (!InputBuffer) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    __try {
        if (InputBuffer->Operation == FS_BPIO_OP_ENABLE) {
            PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
            if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)) && nameInfo) {
                if (NT_SUCCESS(FltParseFileNameInformation(nameInfo))) {
                    if (CheckFileExtensionRule(&nameInfo->Name) || CheckProtectedPathRule(&nameInfo->Name)) {
                        Data->IoStatus.Status = STATUS_NOT_SUPPORTED;
                        FltReleaseFileNameInformation(nameInfo);
                        return FLT_PREOP_COMPLETE;
                    }
                }
                FltReleaseFileNameInformation(nameInfo);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}