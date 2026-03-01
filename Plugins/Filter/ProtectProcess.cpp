#include "DriverCommon.h"

static PVOID ObRegistrationHandle = NULL;
static OB_CALLBACK_REGISTRATION ObRegistration;
static OB_OPERATION_REGISTRATION ObCallbacks[2];

static BOOLEAN IsSystemImage(PUNICODE_STRING FullImageName) {
    if (!FullImageName || !FullImageName->Buffer) return FALSE;

    if (WildcardMatch(L"*\\Windows\\System32\\*", FullImageName->Buffer, FullImageName->Length) ||
        WildcardMatch(L"*\\Windows\\SysWOW64\\*", FullImageName->Buffer, FullImageName->Length) ||
        WildcardMatch(L"*\\Windows\\WinSxS\\*", FullImageName->Buffer, FullImageName->Length) ||
        WildcardMatch(L"*\\Windows\\Microsoft.NET\\*", FullImageName->Buffer, FullImageName->Length) ||
        WildcardMatch(L"*\\Common Files\\Microsoft Shared\\*", FullImageName->Buffer, FullImageName->Length) ||
        WildcardMatch(L"*\\Program Files*\\*", FullImageName->Buffer, FullImageName->Length)) {
        return TRUE;
    }
    return FALSE;
}

VOID ImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
    UNREFERENCED_PARAMETER(ImageInfo);

    if (KeGetCurrentIrql() > APC_LEVEL) return;
    if (!FullImageName || !FullImageName->Buffer) return;
    if (ProcessId == (HANDLE)0) return;

    if (IsSystemImage(FullImageName)) return;

    if (IsTargetProtected(ProcessId)) {
        if (CheckFileExtensionRule(FullImageName)) {
            SendMessageToUser(6001, (ULONG)(ULONG_PTR)ProcessId, FullImageName->Buffer, FullImageName->Length);
        }
    }
}

static BOOLEAN IsBlacklistedAdminTool(HANDLE ProcessId) {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return FALSE;

    NTSTATUS status;
    BOOLEAN isBlacklisted = FALSE;
    PEPROCESS Process = NULL;
    PUNICODE_STRING imageFileName = NULL;

    status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(status)) return FALSE;

    status = SeLocateProcessImageName(Process, &imageFileName);

    if (NT_SUCCESS(status) && imageFileName) {
        if (imageFileName->Buffer) {
            if (WildcardMatch(L"*Taskmgr.exe", imageFileName->Buffer, imageFileName->Length) ||
                WildcardMatch(L"*taskkill.exe", imageFileName->Buffer, imageFileName->Length) ||
                WildcardMatch(L"*ProcessHacker.exe", imageFileName->Buffer, imageFileName->Length) ||
                WildcardMatch(L"*procmon.exe", imageFileName->Buffer, imageFileName->Length)) {
                isBlacklisted = TRUE;
            }
        }
        ExFreePool(imageFileName);
    }

    ObDereferenceObject(Process);
    return isBlacklisted;
}

static OB_PREOP_CALLBACK_STATUS PreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->KernelHandle) return OB_PREOP_SUCCESS;

    PEPROCESS TargetProcess = (PEPROCESS)OperationInformation->Object;
    if (!TargetProcess) return OB_PREOP_SUCCESS;

    HANDLE TargetPid = PsGetProcessId(TargetProcess);
    HANDLE SourcePid = PsGetCurrentProcessId();

    if (SourcePid == TargetPid) return OB_PREOP_SUCCESS;
    if ((ULONG)(ULONG_PTR)SourcePid == GlobalData.PyasPid) return OB_PREOP_SUCCESS;
    if (SourcePid == (HANDLE)4) return OB_PREOP_SUCCESS;

    if (IsTargetProtected(TargetPid)) {
        BOOLEAN bIsTrusted = IsProcessTrusted(SourcePid);

        if (bIsTrusted) {
            if (IsBlacklistedAdminTool(SourcePid)) {
                bIsTrusted = FALSE;
            }
        }

        if (bIsTrusted) return OB_PREOP_SUCCESS;

        ACCESS_MASK DenyMask = PROCESS_TERMINATE |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_CREATE_THREAD |
            PROCESS_VM_READ |
            PROCESS_DUP_HANDLE |
            PROCESS_SUSPEND_RESUME |
            PROCESS_SET_INFORMATION |
            PROCESS_SET_QUOTA;

        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~DenyMask;
        OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess &= ~DenyMask;

        if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~DenyMask;
            OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= ~DenyMask;
        }
    }

    return OB_PREOP_SUCCESS;
}

static OB_PREOP_CALLBACK_STATUS PreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->KernelHandle) return OB_PREOP_SUCCESS;

    PETHREAD TargetThread = (PETHREAD)OperationInformation->Object;
    if (!TargetThread) return OB_PREOP_SUCCESS;

    PEPROCESS TargetProcess = IoThreadToProcess(TargetThread);
    if (!TargetProcess) return OB_PREOP_SUCCESS;

    HANDLE TargetPid = PsGetProcessId(TargetProcess);
    HANDLE SourcePid = PsGetCurrentProcessId();

    if (SourcePid == TargetPid) return OB_PREOP_SUCCESS;
    if ((ULONG)(ULONG_PTR)SourcePid == GlobalData.PyasPid) return OB_PREOP_SUCCESS;
    if (SourcePid == (HANDLE)4) return OB_PREOP_SUCCESS;

    if (IsTargetProtected(TargetPid)) {
        BOOLEAN bIsTrusted = IsProcessTrusted(SourcePid);

        if (bIsTrusted) {
            if (IsBlacklistedAdminTool(SourcePid)) {
                bIsTrusted = FALSE;
            }
        }

        if (bIsTrusted) return OB_PREOP_SUCCESS;

        ACCESS_MASK DenyMask = THREAD_TERMINATE |
            THREAD_SUSPEND_RESUME |
            THREAD_SET_CONTEXT |
            THREAD_SET_INFORMATION |
            THREAD_SET_THREAD_TOKEN;

        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~DenyMask;
        OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess &= ~DenyMask;

        if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~DenyMask;
            OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= ~DenyMask;
        }
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS InitializeProcessProtection() {
    static UNICODE_STRING Altitude = { 0 };
    RtlInitUnicodeString(&Altitude, L"320000");

    ObCallbacks[0].ObjectType = PsProcessType;
    ObCallbacks[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ObCallbacks[0].PreOperation = PreOpenProcess;
    ObCallbacks[0].PostOperation = NULL;

    ObCallbacks[1].ObjectType = PsThreadType;
    ObCallbacks[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ObCallbacks[1].PreOperation = PreOpenThread;
    ObCallbacks[1].PostOperation = NULL;

    ObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    ObRegistration.OperationRegistrationCount = 2;
    ObRegistration.Altitude = Altitude;
    ObRegistration.RegistrationContext = NULL;
    ObRegistration.OperationRegistration = ObCallbacks;

    return ObRegisterCallbacks(&ObRegistration, &ObRegistrationHandle);
}

VOID UninitializeProcessProtection() {
    if (ObRegistrationHandle) {
        ObUnRegisterCallbacks(ObRegistrationHandle);
        ObRegistrationHandle = NULL;
    }
}