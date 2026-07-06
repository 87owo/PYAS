#include "DriverCommon.h"

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() > APC_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo->Name.Buffer || nameInfo->Name.Length == 0) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    HANDLE Pid = PsGetCurrentProcessId();
    FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

    ULONG CreateDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
    BOOLEAN IsCreateAction = (CreateDisposition == FILE_CREATE || CreateDisposition == FILE_SUPERSEDE || CreateDisposition == FILE_OVERWRITE || CreateDisposition == FILE_OVERWRITE_IF || CreateDisposition == FILE_OPEN_IF);
    ULONG DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

    ULONG Operation = 0;
    if (IsCreateAction) Operation |= OP_CREATE;
    if (DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE)) Operation |= OP_WRITE;
    if (DesiredAccess & (DELETE | FILE_DELETE_CHILD)) Operation |= OP_DELETE;

    if (Operation != 0) {
        ULONG RuleCode = 0;
        BOOLEAN Kill = FALSE;
        if (EvaluateFileRule(Pid, &nameInfo->Name, Operation, NULL, 0, &RuleCode, &Kill)) {
            SendMessageToUser(RuleCode, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length);
            QueueRuleProcessTermination(Pid, Kill);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            callbackStatus = FLT_PREOP_COMPLETE;
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return callbackStatus;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() > APC_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (infoClass != FileDispositionInformation && infoClass != FileRenameInformation && infoClass != FileRenameInformationEx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    if (!NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)) || !nameInfo) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!NT_SUCCESS(FltParseFileNameInformation(nameInfo)) || !nameInfo->Name.Buffer) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    HANDLE Pid = PsGetCurrentProcessId();
    FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    ULONG Operation = 0;

    if (infoClass == FileDispositionInformation) {
        Operation = OP_DELETE;
    }
    else {
        Operation = OP_RENAME;
    }

    ULONG RuleCode = 0;
    BOOLEAN Kill = FALSE;
    if (EvaluateFileRule(Pid, &nameInfo->Name, Operation, NULL, 0, &RuleCode, &Kill)) {
        SendMessageToUser(RuleCode, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length);
        QueueRuleProcessTermination(Pid, Kill);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        callbackStatus = FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(nameInfo);
    return callbackStatus;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() > APC_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->Iopb->IrpFlags & (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_NOCACHE)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    ULONG WriteLength = Data->Iopb->Parameters.Write.Length;
    if (WriteLength == 0) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    if (!NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)) || !nameInfo) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!NT_SUCCESS(FltParseFileNameInformation(nameInfo)) || !nameInfo->Name.Buffer) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    HANDLE Pid = PsGetCurrentProcessId();
    FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

    PVOID SystemBuffer = NULL;
    PMDL Mdl = Data->Iopb->Parameters.Write.MdlAddress;
    if (!Mdl && Data->Iopb->Parameters.Write.WriteBuffer && KeGetCurrentIrql() <= APC_LEVEL) {
        if (NT_SUCCESS(FltLockUserBuffer(Data))) Mdl = Data->Iopb->Parameters.Write.MdlAddress;
    }
    if (Mdl) SystemBuffer = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority | MdlMappingNoExecute);

    ULONG RuleCode = 0;
    BOOLEAN Kill = FALSE;
    if (EvaluateFileRule(Pid, &nameInfo->Name, OP_WRITE, SystemBuffer, WriteLength, &RuleCode, &Kill)) {
        SendMessageToUser(RuleCode, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length);
        QueueRuleProcessTermination(Pid, Kill);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        callbackStatus = FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(nameInfo);
    return callbackStatus;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_SetSecurity(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_FileSystemControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}