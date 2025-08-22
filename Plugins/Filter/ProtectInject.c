#include <ntifs.h>
#include "DriverEntry.h"
#include "ProtectMatch.h"

static PVOID g_ObRegHandle = NULL;
static POB_OPERATION_REGISTRATION g_ObOps = NULL;
static OB_CALLBACK_REGISTRATION g_ObReg = { 0 };

static VOID LogAnsi3(PCSTR tag, ULONG upid, PUNICODE_STRING s1, PUNICODE_STRING s2)
{
    ANSI_STRING a1 = { 0 }, a2 = { 0 };
    CHAR buf[1024] = { 0 };
    RtlUnicodeStringToAnsiString(&a1, s1, TRUE);
    if (s2) 
        RtlUnicodeStringToAnsiString(&a2, s2, TRUE);
    RtlStringCchPrintfA(buf, RTL_NUMBER_OF(buf), "%s | %u | %s | %s", tag, upid, a1.Buffer ? a1.Buffer : "", a2.Buffer ? a2.Buffer : "");
    SendPipeLog(buf, strlen(buf));
    RtlFreeAnsiString(&a1);
    RtlFreeAnsiString(&a2);
}

static OB_PREOP_CALLBACK_STATUS PreProcessCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (g_Unloading)
        return OB_PREOP_SUCCESS;
    if (!Info || Info->KernelHandle)
        return OB_PREOP_SUCCESS;
    if (!Info->Object)
        return OB_PREOP_SUCCESS;
    if (Info->Operation != OB_OPERATION_HANDLE_CREATE && Info->Operation != OB_OPERATION_HANDLE_DUPLICATE)
        return OB_PREOP_SUCCESS;
    if (!ExAcquireRundownProtection(&g_Rundown))
        return OB_PREOP_SUCCESS;

    HANDLE cur = PsGetCurrentProcessId();
    if (cur == (HANDLE)0 || cur == (HANDLE)4) {
        ExReleaseRundownProtection(&g_Rundown);
        return OB_PREOP_SUCCESS;
    }
    HANDLE target = PsGetProcessId((PEPROCESS)Info->Object);
    if (target == cur) {
        ExReleaseRundownProtection(&g_Rundown);
        return OB_PREOP_SUCCESS;
    }
    ACCESS_MASK* desired = (Info->Operation == OB_OPERATION_HANDLE_CREATE) ? &Info->Parameters->CreateHandleInformation.DesiredAccess : &Info->Parameters->DuplicateHandleInformation.DesiredAccess;
    ACCESS_MASK mask = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
    PCSTR tn = PsGetProcessImageFileName((PEPROCESS)Info->Object);
    if (tn && (_stricmp(tn, "lsass.exe") == 0))
        mask |= PROCESS_VM_READ;

    if ((*desired & mask) == 0) {
        ExReleaseRundownProtection(&g_Rundown);
        return OB_PREOP_SUCCESS;
    }
    BOOLEAN logok = (KeGetCurrentIrql() == PASSIVE_LEVEL);
    WCHAR cbuf[512] = { 0 }, tbuf[512] = { 0 };
    UNICODE_STRING cexe = { 0 }, texe = { 0 };
    cexe.Buffer = cbuf; cexe.MaximumLength = sizeof(cbuf);
    texe.Buffer = tbuf; texe.MaximumLength = sizeof(tbuf);

    if (logok)
        GetProcessImagePathByPid(cur, &cexe);
    if (logok && IsWhitelist(&cexe)) {
        ExReleaseRundownProtection(&g_Rundown);
        return OB_PREOP_SUCCESS;
    }
    ACCESS_MASK old = *desired;
    *desired &= ~mask;
    if ((*desired) != old && logok) {
        GetProcessImagePathByPid(target, &texe);
        if (cexe.Length == 0) {
            PEPROCESS eproc = PsGetCurrentProcess();
            PCSTR n = PsGetProcessImageFileName(eproc);
            size_t l = n ? strlen(n) : 0;
            for (size_t i = 0; i < l && i < RTL_NUMBER_OF(cbuf) - 1; i++)
                cbuf[i] = (WCHAR)n[i];
            cbuf[l] = 0;
            cexe.Length = (USHORT)(l * sizeof(WCHAR));
        }
        LogAnsi3("INJECT_BLOCK", (ULONG)(ULONG_PTR)cur, &cexe, &texe);
    }
    ExReleaseRundownProtection(&g_Rundown);
    return OB_PREOP_SUCCESS;
}

static OB_PREOP_CALLBACK_STATUS PreThreadCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (!Info || Info->KernelHandle)
        return OB_PREOP_SUCCESS;
    if (Info->Object == NULL)
        return OB_PREOP_SUCCESS;
    if (Info->Operation != OB_OPERATION_HANDLE_CREATE && Info->Operation != OB_OPERATION_HANDLE_DUPLICATE)
        return OB_PREOP_SUCCESS;
    if (!ExAcquireRundownProtection(&g_Rundown))
        return OB_PREOP_SUCCESS;

    HANDLE cur = PsGetCurrentProcessId();
    if (cur == (HANDLE)0 || cur == (HANDLE)4) {
        ExReleaseRundownProtection(&g_Rundown);
        return OB_PREOP_SUCCESS;
    }
    HANDLE owner = PsGetThreadProcessId((PETHREAD)Info->Object);
    if (owner == cur) {
        ExReleaseRundownProtection(&g_Rundown);
        return OB_PREOP_SUCCESS;
    }
    ACCESS_MASK tmask = THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION;
    ACCESS_MASK* desired = (Info->Operation == OB_OPERATION_HANDLE_CREATE) ? &Info->Parameters->CreateHandleInformation.DesiredAccess : &Info->Parameters->DuplicateHandleInformation.DesiredAccess;
    if ((*desired & tmask) == 0) {
        ExReleaseRundownProtection(&g_Rundown);
        return OB_PREOP_SUCCESS;
    }
    BOOLEAN logok = (KeGetCurrentIrql() == PASSIVE_LEVEL);
    WCHAR cbuf[512] = { 0 };
    UNICODE_STRING cexe = { 0 };
    cexe.Buffer = cbuf;
    cexe.MaximumLength = sizeof(cbuf);

    if (logok) 
        GetProcessImagePathByPid(cur, &cexe);
    if (logok && IsWhitelist(&cexe)) {
        ExReleaseRundownProtection(&g_Rundown);
        return OB_PREOP_SUCCESS;
    }
    ACCESS_MASK old = *desired;
    *desired &= ~tmask;
    if ((*desired) != old && logok) {
        if (cexe.Length == 0) {
            PEPROCESS eproc = PsGetCurrentProcess();
            PCSTR n = PsGetProcessImageFileName(eproc);
            size_t l = n ? strlen(n) : 0;
            for (size_t i = 0; i < l && i < RTL_NUMBER_OF(cbuf) - 1; i++)
                cbuf[i] = (WCHAR)n[i];
            cbuf[l] = 0;
            cexe.Length = (USHORT)(l * sizeof(WCHAR));
        }
        UNICODE_STRING tnone = RTL_CONSTANT_STRING(L"None");
        LogAnsi3("THREAD_BLOCK", (ULONG)(ULONG_PTR)cur, &cexe, &tnone);
    }
    ExReleaseRundownProtection(&g_Rundown);
    return OB_PREOP_SUCCESS;
}

NTSTATUS InitInjectProtect(VOID)
{
    static WCHAR obAltBuf[32];
    static UNICODE_STRING obAlt;
    LARGE_INTEGER t = KeQueryPerformanceCounter(NULL);
    RtlStringCchPrintfW(obAltBuf, RTL_NUMBER_OF(obAltBuf), L"385000.%I64x", t.QuadPart);
    RtlInitUnicodeString(&obAlt, obAltBuf);

    g_ObOps = (POB_OPERATION_REGISTRATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(OB_OPERATION_REGISTRATION) * 2, 'bOpr');
    if (!g_ObOps)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(g_ObOps, sizeof(OB_OPERATION_REGISTRATION) * 2);
    g_ObOps[0].ObjectType = PsProcessType;
    g_ObOps[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_ObOps[0].PreOperation = PreProcessCallback;
    g_ObOps[1].ObjectType = PsThreadType;
    g_ObOps[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_ObOps[1].PreOperation = PreThreadCallback;

    RtlZeroMemory(&g_ObReg, sizeof(g_ObReg));
    g_ObReg.Version = OB_FLT_REGISTRATION_VERSION;
    g_ObReg.OperationRegistrationCount = 2;
    g_ObReg.Altitude = obAlt;
    g_ObReg.RegistrationContext = NULL;
    g_ObReg.OperationRegistration = g_ObOps;

    NTSTATUS s = ObRegisterCallbacks(&g_ObReg, &g_ObRegHandle);
    if (!NT_SUCCESS(s)) {
        ExFreePool2(g_ObOps, 'bOpr', NULL, 0);
        g_ObOps = NULL;
        RtlZeroMemory(&g_ObReg, sizeof(g_ObReg));
    }
    return s;
}

VOID UninitInjectProtect(VOID)
{
    if (g_ObRegHandle) {
        ObUnRegisterCallbacks(g_ObRegHandle);
        g_ObRegHandle = NULL;
    }
    if (g_ObOps) {
        ExFreePool2(g_ObOps, 'bOpr', NULL, 0);
        g_ObOps = NULL;
    }
    RtlZeroMemory(&g_ObReg, sizeof(g_ObReg));
}
