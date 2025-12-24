#include <ntifs.h>
#include <fltKernel.h>
#include "DriverEntry.h"
#include "ProtectMatch.h"

#pragma comment(lib, "FltMgr.lib")

PFLT_FILTER g_FilterHandle = NULL;
extern PDRIVER_OBJECT g_DriverObject;
EX_RUNDOWN_REF g_Rundown;

// 定義標誌以便在不同 IRQL 下安全操作
#define MAX_PATH_LEN 512

// 獲取進程名稱 (僅在確定需要攔截時調用，減少性能開銷)
static VOID GetExeNameSafe(HANDLE pid, PUNICODE_STRING exe)
{
    if (!exe || !exe->Buffer || !exe->MaximumLength)
        return;

    exe->Length = 0;

    // 嘗試獲取短名稱 (最安全)
    PEPROCESS cur = PsGetCurrentProcess();
    PCSTR n = NULL;
    if (cur) n = PsGetProcessImageFileName(cur);

    // 如果在 PASSIVE_LEVEL，嘗試獲取完整路徑 (用於精確白名單)
    // 注意：這裡依然有風險，但僅在攔截路徑執行
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        if (GetProcessImagePathByPid(pid, exe)) {
            return;
        }
    }

    // 降級方案：使用短名稱
    size_t l = n ? strlen(n) : 0;
    for (size_t i = 0; i < l && i < (exe->MaximumLength / sizeof(WCHAR)) - 1; i++)
        exe->Buffer[i] = (WCHAR)n[i];
    exe->Buffer[l] = 0;
    exe->Length = (USHORT)(l * sizeof(WCHAR));
}

static BOOLEAN PreOpCheck(VOID)
{
    if (g_Unloading)
        return FALSE;
    if (!ExAcquireRundownProtection(&g_Rundown))
        return FALSE;
    return TRUE;
}

static VOID PostOpRelease(VOID)
{
    ExReleaseRundownProtection(&g_Rundown);
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

static BOOLEAN IsWriteAccess(PFLT_CALLBACK_DATA Data)
{
    // 如果是寫入操作，直接返回
    if (Data->Iopb->MajorFunction == IRP_MJ_WRITE)
        return TRUE;

    // 如果是設置信息 (已經通過 IsDeleteOrRename 過濾)，視為寫入(修改元數據)
    if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION)
        return TRUE;

    // 如果是創建/打開文件，檢查權限
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        ULONG access = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        // 檢查是否包含寫入數據、追加數據、刪除、修改屬性等權限
        if (access & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE |
            WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL)) {
            return TRUE;
        }
    }
    return FALSE;
}

static FLT_PREOP_CALLBACK_STATUS FilePreOp(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // 1. 基礎檢查 (Paging IO 不攔截)
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!PreOpCheck())
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // 2. 獲取 PID
    HANDLE pid = PsGetCurrentProcessId();
    ULONG upid = (ULONG)(ULONG_PTR)pid;

    // 忽略 System (4) 和 Idle (0) 進程，避免系統崩潰
    if (upid == 0 || upid == 4) {
        PostOpRelease();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 3. 檢查操作類型 (僅關心 Create, Write, SetInfo)
    BOOLEAN checkFile = (Data->Iopb->MajorFunction == IRP_MJ_CREATE || Data->Iopb->MajorFunction == IRP_MJ_WRITE);
    BOOLEAN checkSetInfo = (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION);

    if (!checkFile && !checkSetInfo) {
        PostOpRelease();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (checkSetInfo && !IsDeleteOrRename(Data)) {
        PostOpRelease();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 4. 獲取文件名 (這一步最關鍵)
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    // 使用 QUERY_DEFAULT | NORMALIZED 確保獲取標準化路徑
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

    // 5. 邏輯判斷 (優化順序：文件名白名單 -> 黑名單 -> 操作檢查 -> 進程白名單)

    // A. 全局文件白名單 (例如 Windows 目錄下的某些操作)
    if (IsWhitelist(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        PostOpRelease();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // B. 黑名單匹配
    BOOLEAN hitFile = MatchBlockFile(&nameInfo->Name);
    // 勒索防護：必須在敏感目錄 且 有敏感後綴 (如 .txt, .doc)
    // 註：Updater.bat 產生 .txt，應命中這裡
    BOOLEAN hitRansom = MatchBlockRansom(&nameInfo->Name) && HasBlockedSuffix(&nameInfo->Name);

    // 如果沒有命中任何規則，直接放行，節省資源
    if (!hitFile && !hitRansom) {
        FltReleaseFileNameInformation(nameInfo);
        PostOpRelease();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // C. 檢查是否為寫入行為 (讀取不攔截)
    if (!IsWriteAccess(Data)) {
        FltReleaseFileNameInformation(nameInfo);
        PostOpRelease();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // D. 到了這裡，說明命中規則且正在寫入，準備攔截
    //    這時候才去獲取進程名稱，檢查進程白名單
    WCHAR exe_buffer[MAX_PATH_LEN] = { 0 };
    UNICODE_STRING exe = { 0 };
    exe.Buffer = exe_buffer;
    exe.MaximumLength = sizeof(exe_buffer);

    GetExeNameSafe(pid, &exe); // 獲取進程名

    if (IsWhitelistExcept(&exe)) {
        // 進程在白名單中 (如 ntoskrnl, explorer 等)
        FltReleaseFileNameInformation(nameInfo);
        PostOpRelease();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // E. 執行攔截
    if (hitRansom) {
        LogAnsi3("RANSOM_BLOCK", upid, &exe, &nameInfo->Name);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        FltReleaseFileNameInformation(nameInfo);
        PostOpRelease();
        return FLT_PREOP_COMPLETE;
    }

    if (hitFile) {
        LogAnsi3("FILE_BLOCK", upid, &exe, &nameInfo->Name);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        FltReleaseFileNameInformation(nameInfo);
        PostOpRelease();
        return FLT_PREOP_COMPLETE;
    }

    // 默認放行
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
    // 自動附加到所有卷
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
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    FilterUnloadCallback,
    FilterInstanceSetup,
    NULL,
    FilterInstanceTeardownStart,
    FilterInstanceTeardownComplete,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS InitFileProtect(VOID)
{
    ExInitializeRundownProtection(&g_Rundown);

    if (!g_DriverObject)
        return STATUS_UNSUCCESSFUL;

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