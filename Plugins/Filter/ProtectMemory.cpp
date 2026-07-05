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

static BOOLEAN g_ThreadNotifyRegistered = FALSE;
static BOOLEAN g_LoadImageNotifyRegistered = FALSE;

static PACCESS_MASK GetDesiredAccessPointer(POB_PRE_OPERATION_INFORMATION OperationInformation) {
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        return &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    }

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        return &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    return NULL;
}

static ACCESS_MASK GetProcessMemoryDeniedAccess(ULONG Operation) {
    ACCESS_MASK DeniedAccess = 0;

    if (Operation & OP_VM_READ) {
        DeniedAccess |= PROCESS_VM_READ;
    }

    if (Operation & OP_VM_WRITE) {
        DeniedAccess |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;
    }

    return DeniedAccess;
}

static ACCESS_MASK GetProcessControlDeniedAccess(ULONG Operation) {
    ACCESS_MASK DeniedAccess = 0;

    if (Operation & OP_TERMINATE) {
        DeniedAccess |= PROCESS_TERMINATE;
    }

    if (Operation & OP_SUSPEND_RESUME) {
        DeniedAccess |= PROCESS_SUSPEND_RESUME;
    }

    if (Operation & OP_DUP_HANDLE) {
        DeniedAccess |= PROCESS_DUP_HANDLE;
    }

    if (Operation & OP_SET_INFORMATION) {
        DeniedAccess |= PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA;
    }

    return DeniedAccess;
}

static ACCESS_MASK GetThreadMemoryDeniedAccess(ULONG Operation) {
    ACCESS_MASK DeniedAccess = 0;

    if (Operation & OP_VM_WRITE) {
        DeniedAccess |= THREAD_SET_CONTEXT;
    }

    return DeniedAccess;
}

static ACCESS_MASK GetThreadControlDeniedAccess(ULONG Operation) {
    ACCESS_MASK DeniedAccess = 0;

    if (Operation & OP_TERMINATE) {
        DeniedAccess |= THREAD_TERMINATE;
    }

    if (Operation & OP_SUSPEND_RESUME) {
        DeniedAccess |= THREAD_SUSPEND_RESUME;
    }

    if (Operation & OP_SET_INFORMATION) {
        DeniedAccess |= THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN;
    }

    return DeniedAccess;
}

static VOID ReportViolation(ULONG RuleCode, HANDLE SourcePid, HANDLE TargetPid, PCWSTR FallbackMessage) {
    PUNICODE_STRING TargetPath = NULL;
    if (NT_SUCCESS(GetProcessImageName(TargetPid, &TargetPath)) && TargetPath && TargetPath->Buffer) {
        SendMessageToUser(RuleCode, (ULONG)(ULONG_PTR)SourcePid, TargetPath->Buffer, TargetPath->Length);
        ExFreePool(TargetPath);
        return;
    }

    if (TargetPath) ExFreePool(TargetPath);

    UNICODE_STRING MessageString;
    RtlInitUnicodeString(&MessageString, FallbackMessage);
    SendMessageToUser(RuleCode, (ULONG)(ULONG_PTR)SourcePid, MessageString.Buffer, MessageString.Length);
}

BOOLEAN IsAddressInUnmappedMemory(HANDLE ProcessId, PVOID Address) {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return FALSE;

    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(status)) return FALSE;

    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);

    MEMORY_BASIC_INFORMATION MemoryInformation = { 0 };
    SIZE_T ReturnLength = 0;
    status = ZwQueryVirtualMemory(
        ZwCurrentProcess(),
        Address,
        MemoryBasicInformation,
        &MemoryInformation,
        sizeof(MemoryInformation),
        &ReturnLength
    );

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(Process);

    if (!NT_SUCCESS(status)) return FALSE;
    if (!(MemoryInformation.State & MEM_COMMIT)) return FALSE;
    if (!(MemoryInformation.Type & MEM_PRIVATE)) return FALSE;

    return MemoryInformation.Protect == PAGE_EXECUTE_READWRITE ||
        MemoryInformation.Protect == PAGE_EXECUTE_READ ||
        MemoryInformation.Protect == PAGE_EXECUTE ||
        MemoryInformation.Protect == PAGE_EXECUTE_WRITECOPY;
}

static OB_PREOP_CALLBACK_STATUS ObjectPreCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!OperationInformation || OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    PACCESS_MASK DesiredAccess = GetDesiredAccessPointer(OperationInformation);
    if (!DesiredAccess || *DesiredAccess == 0) {
        return OB_PREOP_SUCCESS;
    }

    HANDLE SourcePid = PsGetCurrentProcessId();
    HANDLE TargetPid = NULL;

    if (OperationInformation->ObjectType == *PsProcessType) {
        TargetPid = PsGetProcessId((PEPROCESS)OperationInformation->Object);
        if (!TargetPid || SourcePid == TargetPid || IsProcessTrusted(SourcePid)) {
            return OB_PREOP_SUCCESS;
        }

        ACCESS_MASK OriginalAccess = *DesiredAccess;
        ULONG MemoryOperation = 0;
        ULONG ControlOperation = 0;

        if (OriginalAccess & PROCESS_VM_READ) {
            MemoryOperation |= OP_VM_READ;
        }

        if (OriginalAccess & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)) {
            MemoryOperation |= OP_VM_WRITE;
        }

        if (OriginalAccess & PROCESS_TERMINATE) {
            ControlOperation |= OP_TERMINATE;
        }

        if (OriginalAccess & PROCESS_SUSPEND_RESUME) {
            ControlOperation |= OP_SUSPEND_RESUME;
        }

        if (OriginalAccess & PROCESS_DUP_HANDLE) {
            ControlOperation |= OP_DUP_HANDLE;
        }

        if (OriginalAccess & (PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA)) {
            ControlOperation |= OP_SET_INFORMATION;
        }

        if (MemoryOperation != 0) {
            ULONG RuleCode = 0;
            if (EvaluateMemoryRule(SourcePid, TargetPid, MemoryOperation, &RuleCode)) {
                *DesiredAccess &= ~GetProcessMemoryDeniedAccess(MemoryOperation);
                ReportViolation(RuleCode, SourcePid, TargetPid, L"Memory_Access_Violation");
            }
        }

        if (ControlOperation != 0) {
            ULONG RuleCode = 0;
            if (EvaluateProcessHandleRule(SourcePid, TargetPid, ControlOperation, &RuleCode)) {
                *DesiredAccess &= ~GetProcessControlDeniedAccess(ControlOperation);
                ReportViolation(RuleCode, SourcePid, TargetPid, L"Process_Control_Access_Violation");
            }
        }

        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->ObjectType == *PsThreadType) {
        TargetPid = PsGetThreadProcessId((PETHREAD)OperationInformation->Object);
        if (!TargetPid || SourcePid == TargetPid || IsProcessTrusted(SourcePid)) {
            return OB_PREOP_SUCCESS;
        }

        ACCESS_MASK OriginalAccess = *DesiredAccess;
        ULONG MemoryOperation = 0;
        ULONG ControlOperation = 0;

        if (OriginalAccess & THREAD_SET_CONTEXT) {
            MemoryOperation |= OP_VM_WRITE;
        }

        if (OriginalAccess & THREAD_TERMINATE) {
            ControlOperation |= OP_TERMINATE;
        }

        if (OriginalAccess & THREAD_SUSPEND_RESUME) {
            ControlOperation |= OP_SUSPEND_RESUME;
        }

        if (OriginalAccess & (THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN)) {
            ControlOperation |= OP_SET_INFORMATION;
        }

        if (MemoryOperation != 0) {
            ULONG RuleCode = 0;
            if (EvaluateMemoryRule(SourcePid, TargetPid, MemoryOperation, &RuleCode)) {
                *DesiredAccess &= ~GetThreadMemoryDeniedAccess(MemoryOperation);
                ReportViolation(RuleCode, SourcePid, TargetPid, L"Thread_Context_Manipulation_Shield");
            }
        }

        if (ControlOperation != 0) {
            ULONG RuleCode = 0;
            if (EvaluateProcessHandleRule(SourcePid, TargetPid, ControlOperation, &RuleCode)) {
                *DesiredAccess &= ~GetThreadControlDeniedAccess(ControlOperation);
                ReportViolation(RuleCode, SourcePid, TargetPid, L"Thread_Control_Access_Violation");
            }
        }
    }

    return OB_PREOP_SUCCESS;
}

static VOID ThreadNotifyCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN IsCreated) {
    if (!IsCreated) return;

    HANDLE SourcePid = PsGetCurrentProcessId();
    if (SourcePid == ProcessId) return;
    if (IsProcessTrusted(SourcePid)) return;

    PVOID StartAddress = NULL;
    HANDLE ThreadHandle = NULL;
    CLIENT_ID ClientId = { ProcessId, ThreadId };
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS status = ZwOpenThread(
        &ThreadHandle,
        THREAD_QUERY_INFORMATION,
        &ObjectAttributes,
        &ClientId
    );

    if (NT_SUCCESS(status)) {
        status = ZwQueryInformationThread(
            ThreadHandle,
            (THREADINFOCLASS)THREAD_QUERY_SET_WIN32_START_ADDRESS,
            &StartAddress,
            sizeof(StartAddress),
            NULL
        );
        ZwClose(ThreadHandle);
    }

    if (!NT_SUCCESS(status) || !StartAddress) return;

    ULONG RuleCode = 0;
    if (EvaluateThreadRule(SourcePid, ProcessId, StartAddress, &RuleCode)) {
        ReportViolation(RuleCode, SourcePid, ProcessId, L"Shellcode_Load_Detected");
    }
}

static VOID LoadImageNotifyCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
) {
    if (!FullImageName || !ImageInfo || ImageInfo->SystemModeImage) return;

    ULONG RuleCode = 0;
    if (EvaluateProcessRule(ProcessId, FullImageName, NULL, &RuleCode)) {
        SendMessageToUser(
            RuleCode,
            (ULONG)(ULONG_PTR)ProcessId,
            FullImageName->Buffer,
            FullImageName->Length
        );
    }
}

NTSTATUS InitializeMemoryProtection(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    if (GlobalData.ObRegistrationHandle || g_ThreadNotifyRegistered) {
        return STATUS_SUCCESS;
    }

    NTSTATUS status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    g_ThreadNotifyRegistered = TRUE;

    status = PsSetLoadImageNotifyRoutine(LoadImageNotifyCallback);
    if (NT_SUCCESS(status)) {
        g_LoadImageNotifyRegistered = TRUE;
    }

    OB_OPERATION_REGISTRATION OperationRegistration[2] = { 0 };
    OperationRegistration[0].ObjectType = PsProcessType;
    OperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OperationRegistration[0].PreOperation = ObjectPreCallback;

    OperationRegistration[1].ObjectType = PsThreadType;
    OperationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OperationRegistration[1].PreOperation = ObjectPreCallback;

    OB_CALLBACK_REGISTRATION CallbackRegistration = { 0 };
    CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    CallbackRegistration.OperationRegistrationCount = RTL_NUMBER_OF(OperationRegistration);
    CallbackRegistration.OperationRegistration = OperationRegistration;
    RtlInitUnicodeString(&CallbackRegistration.Altitude, L"320000.PYAS.Ob");

    status = ObRegisterCallbacks(&CallbackRegistration, &GlobalData.ObRegistrationHandle);
    if (NT_SUCCESS(status)) {
        return STATUS_SUCCESS;
    }

    GlobalData.ObRegistrationHandle = NULL;

    if (g_LoadImageNotifyRegistered) {
        PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);
        g_LoadImageNotifyRegistered = FALSE;
    }

    if (g_ThreadNotifyRegistered) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        g_ThreadNotifyRegistered = FALSE;
    }

    return status;
}

VOID UninitializeMemoryProtection() {
    if (GlobalData.ObRegistrationHandle) {
        ObUnRegisterCallbacks(GlobalData.ObRegistrationHandle);
        GlobalData.ObRegistrationHandle = NULL;
    }

    if (g_ThreadNotifyRegistered) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        g_ThreadNotifyRegistered = FALSE;
    }

    if (g_LoadImageNotifyRegistered) {
        PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);
        g_LoadImageNotifyRegistered = FALSE;
    }
}
