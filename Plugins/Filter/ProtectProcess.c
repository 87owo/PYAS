#include <ntifs.h>
#include "DriverEntry.h"

typedef struct _RTL_USER_PROCESS_PARAMETERS RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef NTSTATUS(NTAPI* PFN_RtlCreateProcessParametersEx)(
    PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
    );

typedef NTSTATUS(NTAPI* PFN_RtlDestroyProcessParameters)(
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    );

extern NTSTATUS NTAPI ZwCreateUserProcess(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessCreateFlags,
    ULONG ThreadCreateFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PVOID CreateInfo,
    PVOID AttributeList
);

extern NTSTATUS NTAPI PsSuspendProcess(
    PEPROCESS Process
);

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
static PFN_RtlCreateProcessParametersEx g_RtlCreateProcessParametersEx = NULL;
static PFN_RtlDestroyProcessParameters g_RtlDestroyProcessParameters = NULL;
static BOOLEAN g_ProcNotifyEnabled = FALSE;
static PVOID g_ObCookie = NULL;
static OBCTX g_ObCtx = { 0 };
static HANDLE g_ProtectedPid = NULL;
static PWCH g_ObAltitudeBuf = NULL;
static UNICODE_STRING g_PyasImagePath = { 0 };

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

static NTSTATUS RestartProtectedProcess(VOID)
{
    if (!g_PyasImagePath.Buffer)
        return STATUS_INVALID_PARAMETER;

#ifndef RTL_USER_PROC_PARAMS_NORMALIZED
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x01
#endif

    if (!g_RtlCreateProcessParametersEx || !g_RtlDestroyProcessParameters)
        return STATUS_PROCEDURE_NOT_FOUND;

    HANDLE ph = NULL, th = NULL;
    RTL_USER_PROCESS_PARAMETERS* procParams = NULL;
    NTSTATUS st = g_RtlCreateProcessParametersEx(&procParams, &g_PyasImagePath,
        NULL, NULL, &g_PyasImagePath, NULL, NULL, NULL, NULL, NULL,
        RTL_USER_PROC_PARAMS_NORMALIZED);
    if (!NT_SUCCESS(st))
        return st;

    OBJECT_ATTRIBUTES poa = { 0 };
    OBJECT_ATTRIBUTES toa = { 0 };
    InitializeObjectAttributes(&poa, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&toa, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = ZwCreateUserProcess(&ph, &th, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
        &poa, &toa, 0, 0, procParams, NULL, NULL);

    g_RtlDestroyProcessParameters(procParams);

    if (NT_SUCCESS(st)) {
        ZwClose(th);
        ZwClose(ph);
    }

    return st;
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
            HANDLE cur = PsGetCurrentProcessId();
            if (cur != g_ProtectedPid) {
                ACCESS_MASK da = (Info->Operation == OB_OPERATION_HANDLE_CREATE) ?
                    Info->Parameters->CreateHandleInformation.DesiredAccess :
                    Info->Parameters->DuplicateHandleInformation.DesiredAccess;
                if (da & PROCESS_TERMINATE) {
                    CHAR buf[128] = { 0 };
                    RtlStringCchPrintfA(buf, RTL_NUMBER_OF(buf),
                        "PROC_KILL_ATTEMPT | %u | %u", (ULONG)(ULONG_PTR)cur,
                        (ULONG)(ULONG_PTR)tpid);
                    SendPipeLog(buf, strlen(buf));
                    PsSuspendProcess(PsGetCurrentProcess());
                    RestartProtectedProcess();
                }
                StripProcessAccess(Info);
            }
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
            if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
                SIZE_T len = CreateInfo->ImageFileName->Length;
                PWCH buf = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, len + sizeof(WCHAR), 'apyP');
                if (buf) {
                    RtlCopyMemory(buf, CreateInfo->ImageFileName->Buffer, len);
                    buf[len / sizeof(WCHAR)] = L'\0';
                    if (g_PyasImagePath.Buffer)
                        ExFreePool2(g_PyasImagePath.Buffer, 'apyP', NULL, 0);
                    g_PyasImagePath.Buffer = buf;
                    g_PyasImagePath.Length = (USHORT)len;
                    g_PyasImagePath.MaximumLength = (USHORT)(len + sizeof(WCHAR));
                }
            }
            NTSTATUS s = SetPPL31(Process);
            UpdateProtectedPid(ProcessId);
            LogSet(ProcessId, s);
        }
    }
    else {
        if (g_ProtectedPid && ProcessId == g_ProtectedPid) {
            UpdateProtectedPid(NULL);
            RestartProtectedProcess();
        }
    }
    ExReleaseRundownProtection(&g_Rundown);
}

NTSTATUS InitProcessProtect(VOID)
{
    UNICODE_STRING n = RTL_CONSTANT_STRING(L"PsSetProcessProtection");
    g_PsSetProcessProtection = MmGetSystemRoutineAddress(&n);

    UNICODE_STRING n1 = RTL_CONSTANT_STRING(L"RtlCreateProcessParametersEx");
    g_RtlCreateProcessParametersEx = (PFN_RtlCreateProcessParametersEx)MmGetSystemRoutineAddress(&n1);
    UNICODE_STRING n2 = RTL_CONSTANT_STRING(L"RtlDestroyProcessParameters");
    g_RtlDestroyProcessParameters = (PFN_RtlDestroyProcessParameters)MmGetSystemRoutineAddress(&n2);

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
    if (g_PyasImagePath.Buffer) {
        ExFreePool2(g_PyasImagePath.Buffer, 'apyP', NULL, 0);
        g_PyasImagePath.Buffer = NULL;
        g_PyasImagePath.Length = g_PyasImagePath.MaximumLength = 0;
    }
}
