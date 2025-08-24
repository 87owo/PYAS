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
static PWCH g_ObAltitudeBuf = NULL;

static BOOLEAN IsProcNameEq(PEPROCESS p, PCSTR name)
{
    PCSTR img = PsGetProcessImageFileName(p);
    if (!img || !name) 
        return FALSE;
    
    ANSI_STRING a = { 0 }, b = { 0 };
    RtlInitAnsiString(&a, img);
    RtlInitAnsiString(&b, name);
    return RtlEqualString(&a, &b, TRUE) ? TRUE : FALSE;
}

static NTSTATUS SetPPL31(PEPROCESS p)
{
    if (!g_PsSetProcessProtection) 
        return STATUS_PROCEDURE_NOT_FOUND;
    
    PS_PROTECTION pr = { 0 };
    pr.Level = 0x31;
    ((VOID(NTAPI*)(PEPROCESS, PS_PROTECTION))g_PsSetProcessProtection)(p, pr);
    return STATUS_SUCCESS;
}

static VOID LogSet(HANDLE pid, NTSTATUS st)
{
    CHAR b[128] = { 0 };
    RtlStringCchPrintfA(b, RTL_NUMBER_OF(b), "PROC_PPL_SET | %u | 0x31 | 0x%08X", (ULONG)(ULONG_PTR)pid, st);
    SendPipeLog(b, strlen(b));
}

static VOID UpdateProtectedPid(HANDLE pid)
{
    InterlockedExchangePointer((PVOID*)&g_ProtectedPid, pid);
}

static VOID BootstrapExisting(VOID)
{
    typedef PEPROCESS(NTAPI* PFN_PsGetNextProcess)(PEPROCESS);
    UNICODE_STRING n = RTL_CONSTANT_STRING(L"PsGetNextProcess");
    PFN_PsGetNextProcess fp = (PFN_PsGetNextProcess)MmGetSystemRoutineAddress(&n);
    if (!fp) 
        return;
    
    PEPROCESS p = fp(NULL);
    while (p) {
        if (IsProcNameEq(p, "PYAS.exe")) {
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

static VOID StripProcessAccess(POB_PRE_OPERATION_INFORMATION Info) 
{
    ACCESS_MASK d = PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_SET_INFORMATION | PROCESS_SET_LIMITED_INFORMATION | PROCESS_SUSPEND_RESUME | PROCESS_DUP_HANDLE;
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~d;
    }
    else {
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~d;
    }
}

static VOID StripThreadAccess(POB_PRE_OPERATION_INFORMATION Info)
{
    ACCESS_MASK d = THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION;
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~d;
    }
    else {
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~d;
    }
}

static OB_PREOP_CALLBACK_STATUS ObPreOperation(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    
    if (g_Unloading) 
        return OB_PREOP_SUCCESS;
    if (!Info || Info->KernelHandle) 
        return OB_PREOP_SUCCESS;
    if (!ExAcquireRundownProtection(&g_Rundown)) 
        return OB_PREOP_SUCCESS;
    
    if (Info->ObjectType == g_ObCtx.ProcessType) {
        PEPROCESS pe = (PEPROCESS)Info->Object;
        HANDLE tpid = PsGetProcessId(pe);
        if (g_ProtectedPid && tpid == g_ProtectedPid) {
            if (PsGetCurrentProcessId() != g_ProtectedPid) StripProcessAccess(Info);
        }
    }
    else if (Info->ObjectType == g_ObCtx.ThreadType) {
        PETHREAD th = (PETHREAD)Info->Object;
        HANDLE owner = PsGetThreadProcessId(th);
        if (g_ProtectedPid && owner == g_ProtectedPid) {
            if (PsGetCurrentProcessId() != g_ProtectedPid) StripThreadAccess(Info);
        }
    }
    ExReleaseRundownProtection(&g_Rundown);
    return OB_PREOP_SUCCESS;
}

static NTSTATUS InitObCallbacks(VOID) 
{
    g_ObCtx.ProcessType = *PsProcessType;
    g_ObCtx.ThreadType = *PsThreadType;

    static OB_OPERATION_REGISTRATION ops[2];
    RtlZeroMemory(ops, sizeof(ops));
    ops[0].ObjectType = PsProcessType;
    ops[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[0].PreOperation = ObPreOperation;
    ops[1].ObjectType = PsThreadType;
    ops[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[1].PreOperation = ObPreOperation;

    const WCHAR* altStatic = L"321000";
    USHORT alen = (USHORT)(wcslen(altStatic) * sizeof(WCHAR));
    g_ObAltitudeBuf = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, alen + sizeof(WCHAR), 'tlaO');
    if (!g_ObAltitudeBuf)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(g_ObAltitudeBuf, altStatic, alen);
    g_ObAltitudeBuf[alen / sizeof(WCHAR)] = 0;

    UNICODE_STRING alt = { 0 };
    alt.Buffer = g_ObAltitudeBuf;
    alt.Length = alen;
    alt.MaximumLength = alen;

    OB_CALLBACK_REGISTRATION reg = { 0 };
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 2;
    reg.RegistrationContext = g_ObAltitudeBuf;
    reg.Altitude = alt;
    reg.OperationRegistration = ops;

    NTSTATUS s = ObRegisterCallbacks(&reg, &g_ObCookie);
    if (!NT_SUCCESS(s)) {
        ExFreePool2(g_ObAltitudeBuf, 'tlaO', NULL, 0);
        g_ObAltitudeBuf = NULL;
    }
    return s;
}

static VOID ProcessNotifyEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (g_Unloading)
        return;
    if (!ExAcquireRundownProtection(&g_Rundown))
        return;
    if (CreateInfo) {
        if (IsProcNameEq(Process, "PYAS.exe")) {
            NTSTATUS s = SetPPL31(Process);
            UpdateProtectedPid(ProcessId);
            LogSet(ProcessId, s);
        }
    }
    else {
        if (g_ProtectedPid && ProcessId == g_ProtectedPid) UpdateProtectedPid(NULL);
    }
    ExReleaseRundownProtection(&g_Rundown);
}

NTSTATUS InitProcessProtect(VOID)
{
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

VOID UninitProcessProtect(VOID)
{
    if (g_ProcNotifyEnabled) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyEx, TRUE);
        g_ProcNotifyEnabled = FALSE;
    }
    if (g_ObCookie) {
        ObUnRegisterCallbacks(g_ObCookie);
        g_ObCookie = NULL;
    }
    if (g_ObAltitudeBuf) {
        ExFreePool2(g_ObAltitudeBuf, 'tlaO', NULL, 0);
        g_ObAltitudeBuf = NULL;
    }
}
