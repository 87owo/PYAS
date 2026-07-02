#include "DriverCommon.h"

extern "C" {
    NTSTATUS ZwOpenThread(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );

    NTSTATUS ZwQueryInformationThread(
        HANDLE ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength,
        PULONG ReturnLength
    );
}

#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION 0x0040
#endif

#define THREAD_QUERY_SET_WIN32_START_ADDRESS 9
static BOOLEAN g_LoadImageNotifyRegistered = FALSE;

BOOLEAN IsAddressInUnmappedMemory(HANDLE ProcessId, PVOID Address) {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return FALSE;

    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(status)) return FALSE;

    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);

    MEMORY_BASIC_INFORMATION Mbi = { 0 };
    SIZE_T ReturnLength = 0;
    status = ZwQueryVirtualMemory(ZwCurrentProcess(), Address, MemoryBasicInformation, &Mbi, sizeof(Mbi), &ReturnLength);

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(Process);

    if (NT_SUCCESS(status)) {
        if ((Mbi.State & MEM_COMMIT) && (Mbi.Type & MEM_PRIVATE)) {
            if (Mbi.Protect == PAGE_EXECUTE_READWRITE || Mbi.Protect == PAGE_EXECUTE_READ || Mbi.Protect == PAGE_EXECUTE || Mbi.Protect == PAGE_EXECUTE_WRITECOPY) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static OB_PREOP_CALLBACK_STATUS ObjectPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    ACCESS_MASK DesiredAccess = 0;
    ULONG Operation = 0;
    HANDLE TargetPid = NULL;
    HANDLE SourcePid = PsGetCurrentProcessId();

    if (OperationInformation->ObjectType == *PsProcessType) {
        PEPROCESS TargetProcess = (PEPROCESS)OperationInformation->Object;
        TargetPid = PsGetProcessId(TargetProcess);

        if (SourcePid == TargetPid) return OB_PREOP_SUCCESS;
        if (IsProcessTrusted(SourcePid)) return OB_PREOP_SUCCESS;

        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            DesiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        }
        else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            DesiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        }

        if (DesiredAccess & (PROCESS_VM_READ)) Operation |= OP_VM_READ;
        if (DesiredAccess & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)) Operation |= OP_VM_WRITE;

        if (Operation != 0) {
            ULONG RuleCode = 0;
            if (EvaluateMemoryRule(SourcePid, TargetPid, Operation, &RuleCode)) {
                if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                    OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD);
                }
                else {
                    OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD);
                }
                UNICODE_STRING MsgStr = RTL_CONSTANT_STRING(L"Memory_Access_Violation");
                SendMessageToUser(RuleCode, (ULONG)(ULONG_PTR)SourcePid, MsgStr.Buffer, MsgStr.Length);
            }
        }
    }
    else if (OperationInformation->ObjectType == *PsThreadType) {
        PETHREAD TargetThread = (PETHREAD)OperationInformation->Object;
        TargetPid = PsGetThreadProcessId(TargetThread);

        if (SourcePid == TargetPid) return OB_PREOP_SUCCESS;
        if (IsProcessTrusted(SourcePid)) return OB_PREOP_SUCCESS;

        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            DesiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        }
        else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            DesiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        }

        if (DesiredAccess & (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_TERMINATE)) {
            ULONG RuleCode = 0;
            if (EvaluateMemoryRule(SourcePid, TargetPid, OP_VM_WRITE, &RuleCode)) {
                if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                    OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_TERMINATE);
                }
                else {
                    OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_TERMINATE);
                }
                UNICODE_STRING MsgStr = RTL_CONSTANT_STRING(L"Thread_Context_Manipulation_Shield");
                SendMessageToUser(RuleCode, (ULONG)(ULONG_PTR)SourcePid, MsgStr.Buffer, MsgStr.Length);
            }
        }
    }

    return OB_PREOP_SUCCESS;
}

static VOID ThreadNotifyCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN IsCreated) {
    UNREFERENCED_PARAMETER(ProcessId);

    if (!IsCreated) return;

    HANDLE SourcePid = PsGetCurrentProcessId();
    if (SourcePid == ProcessId) return;
    if (IsProcessTrusted(SourcePid)) return;

    PVOID StartAddress = NULL;
    HANDLE hThread = NULL;
    CLIENT_ID clientId = { (HANDLE)ProcessId, ThreadId };
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    NTSTATUS status = ZwOpenThread(&hThread, THREAD_QUERY_INFORMATION, &oa, &clientId);
    if (NT_SUCCESS(status)) {
        status = ZwQueryInformationThread(hThread, (THREADINFOCLASS)THREAD_QUERY_SET_WIN32_START_ADDRESS, &StartAddress, sizeof(StartAddress), NULL);
        ZwClose(hThread);
    }

    if (!NT_SUCCESS(status) || !StartAddress) return;

    ULONG RuleCode = 0;
    if (EvaluateThreadRule(SourcePid, ProcessId, StartAddress, &RuleCode)) {
        UNICODE_STRING MsgStr = RTL_CONSTANT_STRING(L"Shellcode_Load_Detected");
        SendMessageToUser(RuleCode, (ULONG)(ULONG_PTR)SourcePid, MsgStr.Buffer, MsgStr.Length);
    }
}

static VOID LoadImageNotifyCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
    if (!FullImageName || !ImageInfo) return;
    if (ImageInfo->SystemModeImage) return;

    ULONG RuleCode = 0;
    if (EvaluateProcessRule(ProcessId, FullImageName, NULL, &RuleCode)) {
        UNICODE_STRING MsgStr = RTL_CONSTANT_STRING(L"Suspicious_Module_Load_Detected");
        SendMessageToUser(RuleCode, (ULONG)(ULONG_PTR)ProcessId, FullImageName->Buffer, FullImageName->Length);
    }
}

NTSTATUS InitializeMemoryProtection(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    NTSTATUS status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (!NT_SUCCESS(status)) return status;

    status = PsSetLoadImageNotifyRoutine(LoadImageNotifyCallback);
    if (NT_SUCCESS(status)) {
        g_LoadImageNotifyRegistered = TRUE;
    }

    OB_CALLBACK_REGISTRATION ObRegistration = { 0 };
    OB_OPERATION_REGISTRATION OpRegistration[2] = { 0 };

    OpRegistration[0].ObjectType = PsProcessType;
    OpRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OpRegistration[0].PreOperation = ObjectPreCallback;
    OpRegistration[0].PostOperation = NULL;

    OpRegistration[1].ObjectType = PsThreadType;
    OpRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OpRegistration[1].PreOperation = ObjectPreCallback;
    OpRegistration[1].PostOperation = NULL;

    RtlInitUnicodeString(&ObRegistration.Altitude, L"320000.PYAS.Ob");
    ObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    ObRegistration.RegistrationContext = NULL;
    ObRegistration.OperationRegistrationCount = 2;
    ObRegistration.OperationRegistration = OpRegistration;

    status = ObRegisterCallbacks(&ObRegistration, &GlobalData.ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        if (g_LoadImageNotifyRegistered) {
            PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);
            g_LoadImageNotifyRegistered = FALSE;
        }
        GlobalData.ObRegistrationHandle = NULL;
    }

    return status;
}

VOID UninitializeMemoryProtection() {
    if (GlobalData.ObRegistrationHandle) {
        ObUnRegisterCallbacks(GlobalData.ObRegistrationHandle);
        GlobalData.ObRegistrationHandle = NULL;
    }
    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (g_LoadImageNotifyRegistered) {
        PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);
        g_LoadImageNotifyRegistered = FALSE;
    }
}