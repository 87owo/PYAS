#include <ntifs.h>
#include "DriverEntry.h"
#include "ProtectRules.h"

static BOOLEAN g_ImageNotifyEnabled = FALSE;

static BOOLEAN StrStrI(const wchar_t* s, const wchar_t* sub) {
    if (!s || !sub)
        return FALSE;
    
    size_t n = wcslen(s), m = wcslen(sub);
    if (m == 0 || n < m)
        return FALSE;
    
    for (size_t i = 0; i + m <= n; i++) {
        size_t j = 0;
        for (; j < m; j++) {
            WCHAR a = s[i + j], b = sub[j];
            if (a >= L'A' && a <= L'Z')
                a += 32;
            if (b >= L'A' && b <= L'Z')
                b += 32;
            if (a != b)
                break;
        }
        if (j == m)
            return TRUE;
    }
    return FALSE;
}

static BOOLEAN CheckStackVAD(PVOID a) {
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

static BOOLEAN CheckShellcodeWalkStack(ULONG h) {
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
        if (p && CheckStackVAD(p))
            return TRUE;
    }
    for (ULONG i = 0; i < d; i++) {
        ULONG idx = count - 1 - i;
        if (idx >= d) {
            PVOID p = frames[idx];
            if (p && CheckStackVAD(p))
                return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN IsFrameworkClrPath(const wchar_t* s) {
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
    
    WCHAR exeBuf[512] = { 0 };
    UNICODE_STRING exeName = { 0 };
    exeName.Buffer = exeBuf;
    exeName.MaximumLength = sizeof(exeBuf);
    exeName.Length = 0;
    
    if (!GetProcessImagePathByPid(ProcessId, &exeName)) {
        PEPROCESS eproc = PsGetCurrentProcess();
        PCSTR n = PsGetProcessImageFileName(eproc);
        size_t l = n ? strlen(n) : 0;
        
        for (size_t i = 0; i < l && i < RTL_NUMBER_OF(exeBuf) - 1; i++) 
            exeBuf[i] = (WCHAR)n[i];
        exeBuf[l] = 0;
        exeName.Length = (USHORT)(l * sizeof(WCHAR));
    }
    if (exeName.Length & 1) exeName.Length--;
    {
        size_t elen = exeName.Length / sizeof(WCHAR);
        if ((elen >= 14 && _wcsnicmp(exeName.Buffer + elen - 14, L"powershell.exe", 14) == 0) ||
            (elen >= 8 && _wcsnicmp(exeName.Buffer + elen - 8, L"pwsh.exe", 8) == 0)) {
            ExReleaseRundownProtection(&g_Rundown);
            return; 
        }
    }
    if (IsWhitelist(&exeName)) {
        ExReleaseRundownProtection(&g_Rundown);
        return; 
    }
    CHAR logbuf[1024] = { 0 };
    if (FullImageName && FullImageName->Buffer) {
        if ((StrStrI(FullImageName->Buffer, L"clr.dll") || StrStrI(FullImageName->Buffer, L"mscorwks.dll")) && !IsFrameworkClrPath(FullImageName->Buffer)) {
            RtlStringCchPrintfA(logbuf, sizeof(logbuf), "CLR_BLOCK | %u | %wZ | %wZ", (ULONG)(ULONG_PTR)ProcessId, &exeName, FullImageName);
            SendPipeLog(logbuf, strlen(logbuf));
            ExReleaseRundownProtection(&g_Rundown);
            return;
        }
    }
    if (CheckShellcodeWalkStack(8)) {
        RtlStringCchPrintfA(logbuf, sizeof(logbuf), "SHELLCODE_BLOCK | %u | %wZ | None", (ULONG)(ULONG_PTR)ProcessId, &exeName);
        SendPipeLog(logbuf, strlen(logbuf));
        ExReleaseRundownProtection(&g_Rundown);
        return;
    }
    ExReleaseRundownProtection(&g_Rundown);
}

NTSTATUS InitImageProtect(VOID) {
    NTSTATUS s = PsSetLoadImageNotifyRoutine(ImageLoadNotify);
    if (NT_SUCCESS(s))
        g_ImageNotifyEnabled = TRUE;
    return s;
}

VOID UninitImageProtect(VOID) {
    if (g_ImageNotifyEnabled) {
        PsRemoveLoadImageNotifyRoutine(ImageLoadNotify);
        g_ImageNotifyEnabled = FALSE;
    }
}
