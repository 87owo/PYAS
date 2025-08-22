#include <ntifs.h>
#include "DriverEntry.h"
#include "ProtectRules.h"

static BOOLEAN g_ImageNotifyEnabled = FALSE;

static BOOLEAN StrStrI(const wchar_t* s, const wchar_t* sub)
{
    if (!s || !sub)
        return FALSE;
    size_t n = wcslen(s), m = wcslen(sub);
    if (m == 0 || n < m)
        return FALSE;
    for (size_t i = 0; i + m <= n; i++) {
        size_t j = 0;
        for (; j < m; j++) {
            WCHAR a = s[i + j], b = sub[j];
            if (a >= L'A' && a <= L'Z') a += 32;
            if (b >= L'A' && b <= L'Z') b += 32;
            if (a != b) break;
        }
        if (j == m)
            return TRUE;
    }
    return FALSE;
}

static BOOLEAN CheckVadExec(PVOID a)
{
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    SIZE_T ret = 0;
    NTSTATUS s = ZwQueryVirtualMemory(NtCurrentProcess(), a, MemoryBasicInformation, &mbi, sizeof(mbi), &ret);
    if (!NT_SUCCESS(s))
        return FALSE;
    if (mbi.State != MEM_COMMIT)
        return FALSE;
    if (mbi.Type == SEC_IMAGE)
        return FALSE;
    if (mbi.Type != MEM_PRIVATE && mbi.Type != MEM_MAPPED)
        return FALSE;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

static BOOLEAN WalkForShellcode(ULONG h)
{
#define MAXWALK 20
    PVOID frames[MAXWALK] = { 0 };
    ULONG c = RtlWalkFrameChain(frames, MAXWALK, 1);
    if (c == 0)
        return FALSE;
    ULONG limit = RTL_NUMBER_OF(frames);
    ULONG count = c < limit ? c : limit;
    ULONG d = h < count ? h : count;
    for (ULONG i = 0; i < d; i++) {
        PVOID p = frames[i];
        if (p && CheckVadExec(p))
            return TRUE;
    }
    for (ULONG i = 0; i < d; i++) {
        ULONG idx = count - 1 - i;
        if (idx >= d) {
            PVOID p = frames[idx];
            if (p && CheckVadExec(p))
                return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN IsFrameworkClrPath(const wchar_t* s)
{
    if (!s)
        return FALSE;
    if (!StrStrI(s, L"\\Windows\\Microsoft.NET\\"))
        return FALSE;
    if (!StrStrI(s, L"\\Framework\\") && !StrStrI(s, L"\\Framework64\\"))
        return FALSE;
    if (StrStrI(s, L"\\clr.dll") || StrStrI(s, L"\\mscorwks.dll"))
        return TRUE;
    return FALSE;
}

static VOID LogAnsi3(PCSTR tag, ULONG upid, PUNICODE_STRING s1, PUNICODE_STRING s2)
{
    ANSI_STRING a1 = { 0 }, a2 = { 0 };
    CHAR buf[1024] = { 0 };
    RtlUnicodeStringToAnsiString(&a1, s1, TRUE);
    if (s2) RtlUnicodeStringToAnsiString(&a2, s2, TRUE);
    RtlStringCchPrintfA(buf, RTL_NUMBER_OF(buf), "%s | %u | %s | %s", tag, upid, a1.Buffer ? a1.Buffer : "", a2.Buffer ? a2.Buffer : "");
    SendPipeLog(buf, strlen(buf));
    RtlFreeAnsiString(&a1);
    RtlFreeAnsiString(&a2);
}

static VOID ImageLoadNotify(IN PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);
    if (g_Unloading)
        return;
    if (ProcessId == (HANDLE)0 || ProcessId == (HANDLE)4)
        return;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;
    if (!ExAcquireRundownProtection(&g_Rundown))
        return;

    WCHAR eb[512] = { 0 };
    UNICODE_STRING exe = { 0 };
    exe.Buffer = eb;
    exe.MaximumLength = sizeof(eb);
    exe.Length = 0;

    if (!GetProcessImagePathByPid(ProcessId, &exe)) {
        PEPROCESS eproc = PsGetCurrentProcess();
        PCSTR n = PsGetProcessImageFileName(eproc);
        size_t l = n ? strlen(n) : 0;
        for (size_t i = 0; i < l && i < RTL_NUMBER_OF(eb) - 1; i++)
            eb[i] = (WCHAR)n[i];
        eb[l] = 0;
        exe.Length = (USHORT)(l * sizeof(WCHAR));
    }
    if (exe.Length & 1) exe.Length--;

    {
        size_t elen = exe.Length / sizeof(WCHAR);
        if ((elen >= 14 && _wcsnicmp(exe.Buffer + elen - 14, L"powershell.exe", 14) == 0) ||
            (elen >= 8 && _wcsnicmp(exe.Buffer + elen - 8, L"pwsh.exe", 8) == 0)) {
            ExReleaseRundownProtection(&g_Rundown);
            return;
        }
    }
    if (IsWhitelist(&exe)) {
        ExReleaseRundownProtection(&g_Rundown);
        return;
    }
    if (FullImageName && FullImageName->Buffer) {
        if ((StrStrI(FullImageName->Buffer, L"clr.dll") || StrStrI(FullImageName->Buffer, L"mscorwks.dll")) && !IsFrameworkClrPath(FullImageName->Buffer)) {
            LogAnsi3("CLR_BLOCK", (ULONG)(ULONG_PTR)ProcessId, &exe, FullImageName);
            ExReleaseRundownProtection(&g_Rundown);
            return;
        }
    }
    if (WalkForShellcode(8)) {
        UNICODE_STRING none = RTL_CONSTANT_STRING(L"None");
        LogAnsi3("SHELLCODE_BLOCK", (ULONG)(ULONG_PTR)ProcessId, &exe, &none);
        ExReleaseRundownProtection(&g_Rundown);
        return;
    }
    ExReleaseRundownProtection(&g_Rundown);
}

NTSTATUS InitImageProtect(VOID)
{
    NTSTATUS s = PsSetLoadImageNotifyRoutine(ImageLoadNotify);
    if (NT_SUCCESS(s))
        g_ImageNotifyEnabled = TRUE;
    return s;
}

VOID UninitImageProtect(VOID)
{
    if (g_ImageNotifyEnabled) {
        PsRemoveLoadImageNotifyRoutine(ImageLoadNotify);
        g_ImageNotifyEnabled = FALSE;
    }
}
