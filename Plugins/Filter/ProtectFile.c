#include <ntifs.h>
#include <fltKernel.h>
#include "DriverEntry.h"
#include "ProtectMatch.h"

#pragma comment(lib, "FltMgr.lib")

PFLT_FILTER g_FilterHandle = NULL;
PDRIVER_OBJECT g_DriverObject = NULL;
EX_RUNDOWN_REF g_Rundown;

typedef struct _MINIFILTER_DATA {
    PFLT_FILTER Filter;
} MINIFILTER_DATA, * PMINIFILTER_DATA;

static VOID GetExeNameForLog(HANDLE pid, PUNICODE_STRING exe)
{
    if (!exe || !exe->Buffer || !exe->MaximumLength)
        return;

    exe->Length = 0;
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        if (GetProcessImagePathByPid(pid, exe))
            return;
    }
    PEPROCESS eproc = NULL;
    NTSTATUS s = PsLookupProcessByProcessId(pid, &eproc);
    if (NT_SUCCESS(s) && eproc) {
        PCSTR n = PsGetProcessImageFileName(eproc);
        size_t l = n ? strlen(n) : 0;
        for (size_t i = 0; i < l && i < (exe->MaximumLength / sizeof(WCHAR)) - 1; i++)
            exe->Buffer[i] = (WCHAR)n[i];
        exe->Buffer[l] = 0;
        exe->Length = (USHORT)(l * sizeof(WCHAR));
        ObDereferenceObject(eproc);
        return;
    }
    PCSTR n = NULL;
    PEPROCESS cur = PsGetCurrentProcess();
    if (cur)
        n = PsGetProcessImageFileName(cur);
    size_t l = n ? strlen(n) : 0;
    for (size_t i = 0; i < l && i < (exe->MaximumLength / sizeof(WCHAR)) - 1; i++)
        exe->Buffer[i] = (WCHAR)n[i];
    exe->Buffer[l] = 0;
    exe->Length = (USHORT)(l * sizeof(WCHAR));
}

static BOOLEAN PreOpCheck(ULONG* outUpid)
{
    if (g_Unloading)
        return FALSE;
    if (!ExAcquireRundownProtection(&g_Rundown))
        return FALSE;

    HANDLE pid = PsGetCurrentProcessId();
    ULONG upid = (ULONG)(ULONG_PTR)pid;
    if (upid == 0 || upid == 4) {
        ExReleaseRundownProtection(&g_Rundown);
        return FALSE;
    }
    *outUpid = upid;
    return TRUE;
}

static VOID PostOpRelease()
{
    ExReleaseRundownProtection(&g_Rundown);
}

static BOOLEAN IsExeWhitelisted(ULONG pid)
{
    WCHAR buffer[512] = { 0 };
    UNICODE_STRING exe = { 0 };
    exe.Buffer = buffer;
    exe.MaximumLength = sizeof(buffer);
    GetExeNameForLog((HANDLE)pid, &exe);
    return IsWhitelist(&exe);
}

static BOOLEAN IsDeleteOrRename(PFLT_CALLBACK_DATA Data)
{
    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (infoClass == FileDispositionInformation) {
        PFILE_DISPOSITION_INFORMATION di = (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        return di && di->DeleteFile;
    }
    if (infoClass == FileDispositionInformationEx) {
        PFILE_DISPOSITION_INFORMATION_EX dx = (PFILE_DISPOSITION_INFORMATION_EX)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        return dx && (dx->Flags & FILE_DISPOSITION_DELETE);
    }
    if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx)
        return TRUE;
    return FALSE;
}

static FLT_PREOP_CALLBACK_STATUS CheckAndBlockFile(PFLT_CALLBACK_DATA Data, ULONG upid, PUNICODE_STRING exe)
{
    if (KeGetCurrentIrql() > APC_LEVEL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    BOOLEAN hitFile = MatchBlockFile(&nameInfo->Name);
    BOOLEAN hitRansom = MatchBlockRansom(&nameInfo->Name) && HasBlockedSuffix(&nameInfo->Name);
    BOOLEAN blocked = hitFile || hitRansom;

    if (blocked) {
        LogAnsi3(hitFile && !hitRansom ? "FILE_BLOCK" : "RANSOM_BLOCK", upid, exe, &nameInfo->Name);
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS FilePreOp(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    ULONG upid;
    if (!PreOpCheck(&upid))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        PostOpRelease();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    BOOLEAN checkFile = (Data->Iopb->MajorFunction == IRP_MJ_CREATE || Data->Iopb->MajorFunction == IRP_MJ_WRITE);
    BOOLEAN checkSetInfo = (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION && IsDeleteOrRename(Data));
    if (!checkFile && !checkSetInfo) {
        PostOpRelease();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        PostOpRelease();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        PostOpRelease();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    WCHAR exe_buffer[512] = { 0 };
    UNICODE_STRING exe = { 0 };
    exe.Buffer = exe_buffer;
    exe.MaximumLength = sizeof(exe_buffer);
    GetExeNameForLog(PsGetCurrentProcessId(), &exe);

    BOOLEAN hitFile = MatchBlockFile(&nameInfo->Name);
    BOOLEAN hitRansom = MatchBlockRansom(&nameInfo->Name) && HasBlockedSuffix(&nameInfo->Name);
    BOOLEAN isExcept = IsWhitelistExcept(&exe);

    if ((hitFile || hitRansom) && !isExcept) {
        LogAnsi3(hitFile && !hitRansom ? "FILE_BLOCK" : "RANSOM_BLOCK", upid, &exe, &nameInfo->Name);
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        PostOpRelease();
        return FLT_PREOP_COMPLETE;
    }
    if (isExcept && hitRansom) {
        LogAnsi3("RANSOM_BLOCK", upid, &exe, &nameInfo->Name);
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        PostOpRelease();
        return FLT_PREOP_COMPLETE;
    }
    if (IsWhitelist(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        PostOpRelease();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltReleaseFileNameInformation(nameInfo);
    PostOpRelease();
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static NTSTATUS FilterUnloadCallback(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    g_Unloading = TRUE;
    ExWaitForRundownProtectionRelease(&g_Rundown);
    if (g_FilterHandle != NULL) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS FilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    return STATUS_SUCCESS;
}

static VOID FilterInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

static VOID FilterInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, FilePreOp, NULL },
    { IRP_MJ_WRITE, 0, FilePreOp, NULL },
    { IRP_MJ_SET_INFORMATION, 0, FilePreOp, NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION, 0, NULL, Callbacks, FilterUnloadCallback, FilterInstanceSetup, NULL,
    FilterInstanceTeardownStart, FilterInstanceTeardownComplete, NULL, NULL, NULL, NULL
};

NTSTATUS InitFileProtect(VOID)
{
    ExInitializeRundownProtection(&g_Rundown);
    NTSTATUS status = FltRegisterFilter(g_DriverObject, &FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status))
        return status;

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }
    return status;
}

VOID UninitFileProtect(VOID)
{
    g_Unloading = TRUE;
    ExWaitForRundownProtectionRelease(&g_Rundown);
    if (g_FilterHandle != NULL) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }
}
