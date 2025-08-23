#include <ntifs.h>
#include "DriverEntry.h"

typedef union _PS_PROTECTION {
    UCHAR Level;
    struct {
        UCHAR Type : 3;
        UCHAR Audit : 1;
        UCHAR Signer : 4;
    }Flags;
}PS_PROTECTION, * PPS_PROTECTION;

typedef struct _OBCTX {
    POBJECT_TYPE ProcessType;
    POBJECT_TYPE ThreadType;
}OBCTX, * POBCTX;

static PVOID g_PsSetProcessProtection = NULL;
static BOOLEAN g_ProcNotifyEnabled = FALSE;
static PVOID g_ObCookie = NULL;
static OBCTX g_ObCtx = { 0 };
static HANDLE g_ProtectedPid = NULL;

static BOOLEAN EndsWithNameA(PCSTR s, PCSTR name) {
    if (!s || !name) {
        return FALSE;
    }
    SIZE_T n = strlen(s);
    SIZE_T m = strlen(name);
    if (n < m) {
        return FALSE;
    }
    return _stricmp(s + (n - m), name) == 0;
}

static BOOLEAN EndsWithNameUS(PUNICODE_STRING s, const wchar_t* name) {
    if (!s || !s->Buffer || s->Length == 0 || !name) {
        return FALSE;
    }
    SIZE_T n = s->Length / sizeof(WCHAR);
    SIZE_T m = wcslen(name);
    if (n < m) {
        return FALSE;
    }
    return _wcsnicmp(s->Buffer + (n - m), name, m) == 0;
}

static BOOLEAN IsTargetProcess(PEPROCESS p) {
    if (!p) {
        return FALSE;
    }
    HANDLE pid = PsGetProcessId(p);
    WCHAR buf[512] = { 0 };
    UNICODE_STRING img = { 0 };
    img.Buffer = buf;
    img.MaximumLength = sizeof(buf);
    if (GetProcessImagePathByPid(pid, &img)) {
        if (EndsWithNameUS(&img, L"PYAS.exe")) {
            return TRUE;
        }
        return FALSE;
    }
    return EndsWithNameA(PsGetProcessImageFileName(p), "PYAS.exe");
}

static NTSTATUS SetPPL31(PEPROCESS p) {
    if (!g_PsSetProcessProtection) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    PS_PROTECTION pr = { 0 };
    pr.Level = 0x31;
    ((VOID(NTAPI*)(PEPROCESS, PS_PROTECTION))g_PsSetProcessProtection)(p, pr);
    return STATUS_SUCCESS;
}

static VOID LogSet(HANDLE pid, NTSTATUS st) {
    CHAR b[128] = { 0 };
    RtlStringCchPrintfA(b, RTL_NUMBER_OF(b), "PROC_PPL_SET | %u | 0x31 | 0x%08X", (ULONG)(ULONG_PTR)pid, st);
    SendPipeLog(b, strlen(b));
}

static VOID UpdateProtectedPid(HANDLE pid) {
    InterlockedExchangePointer((PVOID*)&g_ProtectedPid, pid);
}

static VOID BootstrapExisting(VOID) {
    typedef PEPROCESS(NTAPI* PFN_PsGetNextProcess)(PEPROCESS);
    UNICODE_STRING n = RTL_CONSTANT_STRING(L"PsGetNextProcess");
    PFN_PsGetNextProcess fp = (PFN_PsGetNextProcess)MmGetSystemRoutineAddress(&n);
    if (!fp) {
        return;
    }
    PEPROCESS p = fp(NULL);
    while (p) {
        if (IsTargetProcess(p)) {
            HANDLE pid = PsGetProcessId(p);
            NTSTATUS s = SetPPL31(p);
            UpdateProtectedPid(pid);
            LogSet(pid, s);
        }
        PEPROCESS nx = fp(p);
        ObDereferenceObject(p);
        p = nx;
    }
}

static VOID StripProcessAccess(POB_PRE_OPERATION_INFORMATION Info) {
    ACCESS_MASK d = PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_SET_INFORMATION | PROCESS_SET_LIMITED_INFORMATION | PROCESS_SUSPEND_RESUME | PROCESS_DUP_HANDLE;
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~d;
    }
    else {
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~d;
    }
}

static VOID StripThreadAccess(POB_PRE_OPERATION_INFORMATION Info) {
    ACCESS_MASK d = THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION;
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~d;
    }
    else {
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~d;
    }
}

static OB_PREOP_CALLBACK_STATUS ObPreOperation(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info) {
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (g_Unloading) {
        return OB_PREOP_SUCCESS;
    }
    if (!ExAcquireRundownProtection(&g_Rundown)) {
        return OB_PREOP_SUCCESS;
    }
    if (Info->ObjectType == g_ObCtx.ProcessType) {
        PEPROCESS pe = (PEPROCESS)Info->Object;
        HANDLE tpid = PsGetProcessId(pe);
        if (g_ProtectedPid && tpid == g_ProtectedPid) {
            if (PsGetCurrentProcessId() != g_ProtectedPid) {
                StripProcessAccess(Info);
            }
        }
    }
    else if (Info->ObjectType == g_ObCtx.ThreadType) {
        PETHREAD th = (PETHREAD)Info->Object;
        HANDLE owner = PsGetThreadProcessId(th);
        if (g_ProtectedPid && owner == g_ProtectedPid) {
            if (PsGetCurrentProcessId() != g_ProtectedPid) {
                StripThreadAccess(Info);
            }
        }
    }
    ExReleaseRundownProtection(&g_Rundown);
    return OB_PREOP_SUCCESS;
}

static NTSTATUS InitObCallbacks(VOID)
{
    g_ObCtx.ProcessType = *PsProcessType;
    g_ObCtx.ThreadType = *PsThreadType;

    OB_OPERATION_REGISTRATION ops[2] = { 0 };
    ops[0].ObjectType = PsProcessType;
    ops[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[0].PreOperation = ObPreOperation;
    ops[1].ObjectType = PsThreadType;
    ops[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[1].PreOperation = ObPreOperation;

    UNICODE_STRING alt;
    RtlInitUnicodeString(&alt, L"385100");

    OB_CALLBACK_REGISTRATION reg = { 0 };
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 2;
    reg.RegistrationContext = NULL;
    reg.Altitude = alt;
    reg.OperationRegistration = ops;
    return ObRegisterCallbacks(&reg, &g_ObCookie);
}

static VOID ProcessNotifyEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    if (g_Unloading) {
        return;
    }
    if (!ExAcquireRundownProtection(&g_Rundown)) {
        return;
    }
    if (CreateInfo) {
        UNICODE_STRING img = { 0 };
        if (CreateInfo->ImageFileName) {
            img = *CreateInfo->ImageFileName;
        }
        if ((img.Buffer && EndsWithNameUS(&img, L"PYAS.exe")) || (!img.Buffer && IsTargetProcess(Process))) {
            NTSTATUS s = SetPPL31(Process);
            UpdateProtectedPid(ProcessId);
            LogSet(ProcessId, s);
        }
    }
    else {
        if (g_ProtectedPid && ProcessId == g_ProtectedPid) {
            UpdateProtectedPid(NULL);
        }
    }
    ExReleaseRundownProtection(&g_Rundown);
}

NTSTATUS InitProcessProtect(VOID) {
    UNICODE_STRING n = RTL_CONSTANT_STRING(L"PsSetProcessProtection");
    g_PsSetProcessProtection = MmGetSystemRoutineAddress(&n);
    
    NTSTATUS s = InitObCallbacks();
    if (!NT_SUCCESS(s)) 
        return s;
    
    s = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyEx, FALSE);
    if (NT_SUCCESS(s)) 
        g_ProcNotifyEnabled = TRUE;
    BootstrapExisting();
    return STATUS_SUCCESS;
}

VOID UninitProcessProtect(VOID) {
    if (g_ProcNotifyEnabled) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyEx, TRUE);
        g_ProcNotifyEnabled = FALSE;
    }
    if (g_ObCookie) {
        ObUnRegisterCallbacks(g_ObCookie);
        g_ObCookie = NULL;
    }
}
