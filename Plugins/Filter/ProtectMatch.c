#include <ntifs.h>
#include "DriverEntry.h"
#include "ProtectRules.h"
#include "ProtectMatch.h"

static __forceinline BOOLEAN USOK(PUNICODE_STRING s)
{
    return s && s->Buffer && s->Length;
}

static BOOLEAN WildMatchN(const wchar_t* str, SIZE_T n, const wchar_t* pat)
{
    if (*pat == 0)
        return n == 0;

    if (*pat == L'*') {
        if (pat[1] == L'*') {
            for (SIZE_T i = 0; i <= n; ++i)
                if (WildMatchN(str + i, n - i, pat + 2))
                    return TRUE;
            return FALSE;
        }
        SIZE_T i = 0;
        for (; i < n && str[i] != L'\\'; ++i)
            if (WildMatchN(str + i, n - i, pat + 1))
                return TRUE;
        return WildMatchN(str + i, n - i, pat + 1);
    }
    if (*pat == L'?')
        return n > 0 && str[0] != L'\\' && WildMatchN(str + 1, n - 1, pat + 1);
    if (n == 0)
        return FALSE;

    WCHAR sc = str[0], pc = *pat;
    if (sc >= L'A' && sc <= L'Z')
        sc += 32;
    if (pc >= L'A' && pc <= L'Z')
        pc += 32;
    return sc == pc && WildMatchN(str + 1, n - 1, pat + 1);
}

static BOOLEAN MatchList(PUNICODE_STRING s, wchar_t** list)
{
    if (!USOK(s) || !list) 
        return FALSE;
    
    SIZE_T s_len = s->Length / sizeof(WCHAR);
    for (SIZE_T i = 0; list[i]; ++i) {
        wchar_t* pat = list[i];
        if (wcschr(pat, L'*') || wcschr(pat, L'?')) {
            if (WildMatchN(s->Buffer, s_len, pat)) 
                return TRUE;
        }
        else {
            SIZE_T pat_len = wcslen(pat);
            if (s_len >= pat_len && _wcsnicmp(s->Buffer, pat, pat_len) == 0) {
                if (s_len == pat_len || s->Buffer[s_len - pat_len - 1] == L'\\') {
                    return TRUE;
                }
            }
            if (s_len >= pat_len && _wcsnicmp(s->Buffer + s_len - pat_len, pat, pat_len) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static wchar_t* MatchListGetRule(PUNICODE_STRING s, wchar_t** list)
{
    if (!USOK(s) || !list) 
        return 0;
   
    SIZE_T s_len = s->Length / sizeof(WCHAR);
    for (SIZE_T i = 0; list[i]; ++i) {
        wchar_t* pat = list[i];
        if (wcschr(pat, L'*') || wcschr(pat, L'?')) {
            if (WildMatchN(s->Buffer, s_len, pat))
                return pat;
        }
        else {
            SIZE_T pat_len = wcslen(pat);
            if (s_len >= pat_len && _wcsnicmp(s->Buffer, pat, pat_len) == 0) {
                if (s_len == pat_len || s->Buffer[s_len - pat_len - 1] == L'\\') {
                    return pat;
                }
            }
            if (s_len >= pat_len && _wcsnicmp(s->Buffer + s_len - pat_len, pat, pat_len) == 0) {
                return pat;
            }
        }
    }
    return 0;
}

static BOOLEAN StrStrIW(const wchar_t* s, const wchar_t* sub) 
{
    if (!s || !sub) 
        return FALSE;
    
    SIZE_T n = wcslen(s), m = wcslen(sub);
    if (m == 0 || n < m) 
        return FALSE;
    
    for (SIZE_T i = 0; i + m <= n; i++) {
        if (_wcsnicmp(s + i, sub, m) == 0) 
            return TRUE;
    }
    return FALSE;
}

static BOOLEAN EndsWithNameUS(PUNICODE_STRING s, const wchar_t* name)
{
    if (!USOK(s) || !name)
        return FALSE;
    
    SIZE_T n = s->Length / sizeof(WCHAR);
    SIZE_T m = wcslen(name);
    return n >= m && _wcsnicmp(s->Buffer + (n - m), name, m) == 0;
}

BOOLEAN IsRegistryBlock(PUNICODE_STRING key, PUNICODE_STRING valueName, PUNICODE_STRING exe)
{
    if (USOK(key) && WildMatchN(key->Buffer, key->Length / sizeof(WCHAR), L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\**"))
        return FALSE;

    if (USOK(exe) && IsWhitelist(exe))
        return FALSE;

    if (USOK(exe) && USOK(key)) {
        if ((EndsWithNameUS(exe, L"services.exe") || EndsWithNameUS(exe, L"svchost.exe") || EndsWithNameUS(exe, L"sc.exe")) &&
            WildMatchN(key->Buffer, key->Length / sizeof(WCHAR), L"\\REGISTRY\\**\\SYSTEM\\CurrentControlSet\\Services\\**"))
            return FALSE;

        if ((EndsWithNameUS(exe, L"powershell.exe") || EndsWithNameUS(exe, L"pwsh.exe")) &&
            (WildMatchN(key->Buffer, key->Length / sizeof(WCHAR), L"\\REGISTRY\\**\\CurrentVersion\\Internet Settings\\ZoneMap\\**") ||
                WildMatchN(key->Buffer, key->Length / sizeof(WCHAR), L"\\REGISTRY\\**\\CurrentVersion\\Internet Settings\\ZoneMap") ||
                WildMatchN(key->Buffer, key->Length / sizeof(WCHAR), L"\\REGISTRY\\**\\CurrentVersion\\Notifications\\Data\\**") ||
                WildMatchN(key->Buffer, key->Length / sizeof(WCHAR), L"\\REGISTRY\\**\\CurrentVersion\\Notifications\\Data")))
            return FALSE;

        if ((EndsWithNameUS(exe, L"msiexec.exe") || EndsWithNameUS(exe, L"TrustedInstaller.exe")) &&
            (WildMatchN(key->Buffer, key->Length / sizeof(WCHAR), L"\\REGISTRY\\**\\CurrentVersion\\Installer\\**") ||
                WildMatchN(key->Buffer, key->Length / sizeof(WCHAR), L"\\REGISTRY\\**\\CurrentVersion\\Uninstall\\**") ||
                WildMatchN(key->Buffer, key->Length / sizeof(WCHAR), L"\\REGISTRY\\**\\SYSTEM\\CurrentControlSet\\Services\\**")))
            return FALSE;

        if (EndsWithNameUS(exe, L"schtasks.exe") && WildMatchN(key->Buffer, key->Length / sizeof(WCHAR), L"\\REGISTRY\\**\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\**"))
            return FALSE;
    }
    if (USOK(key) && MatchBlockReg(key))
        return TRUE;

    if (USOK(valueName)) {
        for (SIZE_T i = 0; g_BlockReg[i]; ++i) {
            wchar_t* pat = g_BlockReg[i];
            if (!wcschr(pat, L'\\') && !wcschr(pat, L'*') && !wcschr(pat, L'?') && _wcsnicmp(valueName->Buffer, pat, wcslen(pat)) == 0)
                return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN GetProcessImagePathByPid(HANDLE pid, PUNICODE_STRING ProcessImagePath)
{
    PEPROCESS process = NULL;
    PVOID buf = NULL;
    HANDLE h = NULL;
    NTSTATUS status;
    ULONG len = 0;

    status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status)) 
        return FALSE;

    status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL, PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, KernelMode, &h);
    if (!NT_SUCCESS(status))
        goto cleanup;

    status = ZwQueryInformationProcess(h, ProcessImageFileName, NULL, 0, &len);
    if (status != STATUS_INFO_LENGTH_MISMATCH || len == 0)
        goto cleanup;

    buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, len, 'iPgN');
    if (!buf)
        goto cleanup;

    status = ZwQueryInformationProcess(h, ProcessImageFileName, buf, len, &len);
    if (NT_SUCCESS(status)) {
        PUNICODE_STRING image = (PUNICODE_STRING)buf;
        if (image->Buffer && image->Length > 0 && ProcessImagePath->MaximumLength >= image->Length + sizeof(WCHAR)) {
            RtlCopyMemory(ProcessImagePath->Buffer, image->Buffer, image->Length);
            ProcessImagePath->Length = image->Length;
            ProcessImagePath->Buffer[image->Length / sizeof(WCHAR)] = 0;
            status = TRUE;
        }
        else {
            status = FALSE;
        }
    }
    else {
        status = FALSE;
    }
cleanup:
    if (buf) 
        ExFreePool2(buf, 'iPgN', NULL, 0);
    if (h)
        ZwClose(h);
    if (process)
        ObDereferenceObject(process);
    return NT_SUCCESS(status);
}

BOOLEAN IsWhitelist(PUNICODE_STRING s)
{
    if (MatchList(s, g_WhitelistExcept)) 
        return FALSE;
    return MatchList(s, g_Whitelist);
}

BOOLEAN MatchBlockReg(PUNICODE_STRING s)
{
    return MatchList(s, g_BlockReg);
}

wchar_t* GetMatchedBlockRegRule(PUNICODE_STRING s) 
{
    return MatchListGetRule(s, g_BlockReg);
}

BOOLEAN MatchBlockFile(PUNICODE_STRING s)
{
    return MatchList(s, g_BlockFile);
}

BOOLEAN MatchBlockRansom(PUNICODE_STRING s)
{
    return MatchList(s, g_BlockRansom);
}

wchar_t* GetMatchedBlockFileRule(PUNICODE_STRING s) 
{
    return MatchListGetRule(s, g_BlockFile);
}

BOOLEAN HasBlockedSuffix(PUNICODE_STRING s)
{
    if (!USOK(s)) {
        return FALSE;
    }
    for (SIZE_T i = 0; g_Blocksuffix[i]; ++i) {
        if (EndsWithNameUS(s, g_Blocksuffix[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN MatchRemoteSuspectBin(PUNICODE_STRING img)
{
    if (!USOK(img)) 
        return FALSE;
    
    for (SIZE_T i = 0; g_RemoteSuspectBins[i]; ++i)
        if (EndsWithNameUS(img, g_RemoteSuspectBins[i]))
            return TRUE;
    return FALSE;
}

BOOLEAN MatchRemoteCommand(PUNICODE_STRING cmd, PUNICODE_STRING img)
{
    if (!USOK(cmd)) 
        return FALSE;
    
    const wchar_t* s = cmd->Buffer;
    for (SIZE_T i = 0; g_RemoteCmdIndicatorsHttp[i]; ++i)
        if (StrStrIW(s, g_RemoteCmdIndicatorsHttp[i])) 
            return TRUE;
    
    for (SIZE_T i = 0; g_RemoteCmdIndicatorsGeneric[i]; ++i)
        if (StrStrIW(s, g_RemoteCmdIndicatorsGeneric[i])) 
            return TRUE;
    
    if (USOK(img) && EndsWithNameUS(img, L"cmd.exe")) {
        for (SIZE_T i = 0; g_RemoteCmdFromCmdExe[i]; ++i)
            if (StrStrIW(s, g_RemoteCmdFromCmdExe[i])) 
                return TRUE;
    }
    if (USOK(img) && EndsWithNameUS(img, L"rundll32.exe")) {
        for (SIZE_T i = 0; g_RemoteCmdFromRundll32Exe[i]; ++i)
            if (StrStrIW(s, g_RemoteCmdFromRundll32Exe[i]))
                return TRUE;
    }
    if (USOK(img) && EndsWithNameUS(img, L"regsvr32.exe") && StrStrIW(s, L"/i:") && StrStrIW(s, L"http")) 
        return TRUE;
    
    if (USOK(img) && EndsWithNameUS(img, L"mshta.exe")) {
        for (SIZE_T i = 0; g_RemoteCmdFromMshtaExe[i]; ++i)
            if (StrStrIW(s, g_RemoteCmdFromMshtaExe[i]))
                return TRUE;
    }
    return FALSE;
}

BOOLEAN MatchScreenCapModule(PUNICODE_STRING mod)
{
    if (!USOK(mod)) 
        return FALSE;
    
    for (SIZE_T i = 0; g_ScreenCapModules[i]; ++i)
        if (EndsWithNameUS(mod, g_ScreenCapModules[i]))
            return TRUE;
    return FALSE;
}

BOOLEAN MatchSuspiciousProcPath(PUNICODE_STRING img)
{
    if (!USOK(img)) 
        return FALSE;
    
    const wchar_t* s = img->Buffer;
    if (StrStrIW(s, L"\\Users\\")) {
        for (SIZE_T i = 0; g_ScreenUserSubdirs[i]; ++i)
            if (StrStrIW(s, g_ScreenUserSubdirs[i])) 
                return TRUE;
    }
    for (SIZE_T i = 0; g_ScreenOtherProcNeedles[i]; ++i)
        if (StrStrIW(s, g_ScreenOtherProcNeedles[i])) 
            return TRUE;
    return FALSE;
}

BOOLEAN MatchClrFromNonFramework(PUNICODE_STRING fullImageName) 
{
    if (!USOK(fullImageName)) 
        return FALSE;
    
    const wchar_t* s = fullImageName->Buffer;
    return (StrStrIW(s, L"\\clr.dll") || StrStrIW(s, L"\\mscorwks.dll")) && !StrStrIW(s, L"\\Windows\\Microsoft.NET\\") && !StrStrIW(s, L"\\Framework");
}

BOOLEAN IsWhitelistExcept(PUNICODE_STRING img)
{
    if (!USOK(img)) 
        return FALSE;
    
    return MatchList(img, g_WhitelistExcept);
}
