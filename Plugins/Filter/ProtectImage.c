#include <ntifs.h>
#include "DriverEntry.h"
#include "ProtectMatch.h"

static BOOLEAN g_ImageNotifyEnabled = FALSE;

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
        if (MatchClrFromNonFramework(FullImageName)) {
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
