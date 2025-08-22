#include <ntifs.h>
#include "DriverEntry.h"
#include "ProtectMatch.h"

static BOOLEAN g_RemoteNotifyEnabled = FALSE;

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

static VOID ProcessNotifyEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);
    
    if (!CreateInfo)
        return;
    if (g_Unloading)
        return;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;
    if (!ExAcquireRundownProtection(&g_Rundown))
        return;

    HANDLE ppid = CreateInfo->CreatingThreadId.UniqueProcess;
    if (ppid == (HANDLE)0 || ppid == (HANDLE)4) {
        ExReleaseRundownProtection(&g_Rundown);
        return;
    }
    UNICODE_STRING parent = { 0 };
    WCHAR pbuf[512] = { 0 };
    parent.Buffer = pbuf;
    parent.MaximumLength = sizeof(pbuf);

    if (!GetProcessImagePathByPid(ppid, &parent)) {
        PEPROCESS eproc = PsGetCurrentProcess();
        PCSTR n = PsGetProcessImageFileName(eproc);
        size_t l = n ? strlen(n) : 0;
        for (size_t i = 0; i < l && i < RTL_NUMBER_OF(pbuf) - 1; i++)
            pbuf[i] = (WCHAR)n[i];
        pbuf[l] = 0;
        parent.Length = (USHORT)(l * sizeof(WCHAR));
    }
    if (IsWhitelist(&parent)) {
        ExReleaseRundownProtection(&g_Rundown);
        return;
    }
    UNICODE_STRING img = { 0 };
    if (CreateInfo->ImageFileName)
        img = *CreateInfo->ImageFileName;
    UNICODE_STRING cmd = { 0 };
    if (CreateInfo->CommandLine)
        cmd = *CreateInfo->CommandLine;

    BOOLEAN suspect = FALSE;
    if (MatchRemoteSuspectBin(&img) && MatchRemoteCommand(&cmd, &img))
        suspect = TRUE;

    if (suspect) {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        if (cmd.Buffer && cmd.Length)
            LogAnsi3("REMOTE_BLOCK", (ULONG)(ULONG_PTR)ppid, &parent, &cmd);
        else if (img.Buffer && img.Length)
            LogAnsi3("REMOTE_BLOCK", (ULONG)(ULONG_PTR)ppid, &parent, &img);
        else {
            UNICODE_STRING none = RTL_CONSTANT_STRING(L"None");
            LogAnsi3("REMOTE_BLOCK", (ULONG)(ULONG_PTR)ppid, &parent, &none);
        }
    }
    ExReleaseRundownProtection(&g_Rundown);
}

NTSTATUS InitRemoteProtect(VOID)
{
    NTSTATUS s = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyEx, FALSE);
    if (NT_SUCCESS(s))
        g_RemoteNotifyEnabled = TRUE;
    return s;
}

VOID UninitRemoteProtect(VOID)
{
    if (g_RemoteNotifyEnabled) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyEx, TRUE);
        g_RemoteNotifyEnabled = FALSE;
    }
}
