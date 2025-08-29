#include <ntifs.h>
#include <ntstrsafe.h>
#include "DriverEntry.h"

typedef union _PS_PROTECTION {
    UCHAR Level;
    struct {
        UCHAR Type : 3;
        UCHAR Audit : 1;
        UCHAR Signer : 4;
    } Flags;
} PS_PROTECTION, * PPS_PROTECTION;

static PVOID g_PsSetProcessProtection = NULL;
static HANDLE g_ProtectedPid = NULL;
static PVOID g_ObCookie = NULL;

static NTSTATUS SetPPL31(_In_ PEPROCESS proc)
{
    if (!proc || !g_PsSetProcessProtection)
        return STATUS_PROCEDURE_NOT_FOUND;

    PS_PROTECTION p = { 0 };
    p.Level = 0x31;
    ((VOID(NTAPI*)(PEPROCESS, PS_PROTECTION))g_PsSetProcessProtection)(proc, p);
    return STATUS_SUCCESS;
}

static OB_PREOP_CALLBACK_STATUS ObPreOperation(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION info
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!info || info->KernelHandle)
        return OB_PREOP_SUCCESS;

    if (info->ObjectType == *PsProcessType) {
        PEPROCESS proc = (PEPROCESS)info->Object;
        HANDLE pid = PsGetProcessId(proc);
        if (g_ProtectedPid && pid == g_ProtectedPid && PsGetCurrentProcessId() != g_ProtectedPid) {
            ACCESS_MASK* mask = (info->Operation == OB_OPERATION_HANDLE_CREATE)
                ? &info->Parameters->CreateHandleInformation.DesiredAccess
                : &info->Parameters->DuplicateHandleInformation.DesiredAccess;

            if (*mask & PROCESS_TERMINATE) {
                LogAnsi3("KILL_ATTEMPT",
                    (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                    NULL, NULL);
                *mask &= ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD);
            }
        }
    }
    return OB_PREOP_SUCCESS;
}

static VOID ProcessNotify(
    _In_opt_ PEPROCESS Process,
    _In_ HANDLE Pid,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNICODE_STRING target = RTL_CONSTANT_STRING(L"\\??\\C:\\PYAS.exe");
    if (CreateInfo) {
        if (Process && CreateInfo->ImageFileName &&
            RtlEqualUnicodeString(CreateInfo->ImageFileName, &target, TRUE)) {

            NTSTATUS st = SetPPL31(Process);
            UNREFERENCED_PARAMETER(st);

            InterlockedExchangePointer((PVOID*)&g_ProtectedPid, Pid);
            LogAnsi3("PROC_PPL", (ULONG)(ULONG_PTR)Pid, (PUNICODE_STRING)CreateInfo->ImageFileName, NULL);
        }
    }
    else {
        if (g_ProtectedPid && Pid == g_ProtectedPid) {
            InterlockedExchangePointer((PVOID*)&g_ProtectedPid, NULL);
        }
    }
}

NTSTATUS InitProcessProtect(VOID)
{
    UNICODE_STRING n = RTL_CONSTANT_STRING(L"PsSetProcessProtection");
    g_PsSetProcessProtection = MmGetSystemRoutineAddress(&n);

    static OB_OPERATION_REGISTRATION ops[1];
    RtlZeroMemory(ops, sizeof(ops));
    ops[0].ObjectType = PsProcessType;
    ops[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[0].PreOperation = ObPreOperation;
    ops[0].PostOperation = NULL;

    UNICODE_STRING alt = RTL_CONSTANT_STRING(L"321000");
    OB_CALLBACK_REGISTRATION reg;
    RtlZeroMemory(&reg, sizeof(reg));
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 1;
    reg.OperationRegistration = ops;
    reg.RegistrationContext = NULL;
    reg.Altitude = alt;

    NTSTATUS s = ObRegisterCallbacks(&reg, &g_ObCookie);
    if (!NT_SUCCESS(s)) {
        g_ObCookie = NULL;
        return s;
    }
    s = PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE);
    if (!NT_SUCCESS(s)) {
        ObUnRegisterCallbacks(g_ObCookie);
        g_ObCookie = NULL;
        return s;
    }
    return STATUS_SUCCESS;
}

VOID UninitProcessProtect(VOID)
{
    if (g_ObCookie) {
        ObUnRegisterCallbacks(g_ObCookie);
        g_ObCookie = NULL;
    }
    PsSetCreateProcessNotifyRoutineEx(ProcessNotify, TRUE);
}
