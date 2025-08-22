#include <ntifs.h>
#include "DriverEntry.h"
#include "ProtectMatch.h"

static BOOLEAN g_ScreenImgCb = FALSE;

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

static VOID ImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);
    if (g_Unloading)
        return;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;
    if (!ExAcquireRundownProtection(&g_Rundown))
        return;
    if (!FullImageName || !FullImageName->Buffer || FullImageName->Length == 0) {
        ExReleaseRundownProtection(&g_Rundown);
        return;
    }

    UNICODE_STRING proc = { 0 };
    WCHAR pbuf[512] = { 0 };
    proc.Buffer = pbuf;
    proc.MaximumLength = sizeof(pbuf);

    if (!GetProcessImagePathByPid(ProcessId, &proc)) {
        PEPROCESS eproc = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &eproc))) {
            PCSTR n = PsGetProcessImageFileName(eproc);
            SIZE_T l = n ? strlen(n) : 0;
            for (SIZE_T i = 0; i < l && i < RTL_NUMBER_OF(pbuf) - 1; i++)
                pbuf[i] = (WCHAR)n[i];
            pbuf[l] = 0;
            proc.Length = (USHORT)(l * sizeof(WCHAR));
            ObDereferenceObject(eproc);
        }
    }
    if (proc.Length == 0) {
        ExReleaseRundownProtection(&g_Rundown);
        return;
    }
    if (IsWhitelist(&proc)) {
        ExReleaseRundownProtection(&g_Rundown);
        return;
    }

    BOOLEAN suspicious = MatchSuspiciousProcPath(&proc);
    if (suspicious && MatchScreenCapModule(FullImageName))
        LogAnsi3("SCREEN_BLOCK", (ULONG)(ULONG_PTR)ProcessId, &proc, FullImageName);

    ExReleaseRundownProtection(&g_Rundown);
}

NTSTATUS InitScreenProtect(VOID)
{
    NTSTATUS s = PsSetLoadImageNotifyRoutine(ImageLoadNotify);
    if (NT_SUCCESS(s)) g_ScreenImgCb = TRUE;
    return s;
}

VOID UninitScreenProtect(VOID)
{
    if (g_ScreenImgCb) {
        PsRemoveLoadImageNotifyRoutine(ImageLoadNotify);
        g_ScreenImgCb = FALSE;
    }
}
