#include "DriverCommon.h"

PVOID ObRegistrationHandle = NULL;
OB_CALLBACK_REGISTRATION ObRegistration;
OB_OPERATION_REGISTRATION ObCallbacks[1];

static BOOLEAN IsSystemImage(PUNICODE_STRING FullImageName) {
    if (!FullImageName || !FullImageName->Buffer) return FALSE;

    if (wcsstr(FullImageName->Buffer, L"\\Windows\\System32\\") ||
        wcsstr(FullImageName->Buffer, L"\\Windows\\SysWOW64\\") ||
        wcsstr(FullImageName->Buffer, L"\\Windows\\WinSxS\\")) {
        return TRUE;
    }
    return FALSE;
}

VOID ImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
    UNREFERENCED_PARAMETER(ImageInfo);

    if (!FullImageName || !FullImageName->Buffer) return;
    if (ProcessId == (HANDLE)0) return;

    if (IsSystemImage(FullImageName)) return;

    if (IsTargetProtected(ProcessId)) {
        if (CheckFileExtensionRule(FullImageName)) {
            SendMessageToUser(6001, (ULONG)(ULONG_PTR)ProcessId, FullImageName->Buffer);
        }
    }
}

static OB_PREOP_CALLBACK_STATUS PreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->KernelHandle) return OB_PREOP_SUCCESS;

    PEPROCESS TargetProcess = (PEPROCESS)OperationInformation->Object;
    HANDLE TargetPid = PsGetProcessId(TargetProcess);
    HANDLE SourcePid = PsGetCurrentProcessId();

    if (SourcePid == TargetPid) return OB_PREOP_SUCCESS;
    if (IsProcessTrusted(SourcePid)) return OB_PREOP_SUCCESS;
    if (IsInstallerProcess(SourcePid)) return OB_PREOP_SUCCESS;

    BOOLEAN bProtected = IsTargetProtected(TargetPid);

    if (bProtected) {
        ACCESS_MASK DenyMask = PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_READ | PROCESS_DUP_HANDLE;

        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~DenyMask;
        OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess &= ~DenyMask;
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

    ObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    ObRegistration.OperationRegistrationCount = 1;
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