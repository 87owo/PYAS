#include <ntifs.h>
#include "DriverEntry.h"
#include "ProtectRules.h"
#include "ProtectMatch.h"

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
    if (!s || !s->Buffer || s->Length == 0)
        return FALSE;
    
    size_t s_len = s->Length / sizeof(WCHAR);
    for (SIZE_T i = 0; list[i]; ++i) {
        wchar_t* pat = list[i];
        size_t pat_len = wcslen(pat);
        if (wcschr(pat, L'*') || wcschr(pat, L'?')) {
            if (WildMatchN(s->Buffer, s_len, pat))
                return TRUE;
        }
        else {
            if (s_len == pat_len && _wcsnicmp(s->Buffer, pat, pat_len) == 0)
                return TRUE;
            if (s_len > pat_len && _wcsnicmp(s->Buffer + s_len - pat_len, pat, pat_len) == 0)
                return TRUE;
            if (s_len > pat_len && _wcsnicmp(s->Buffer, pat, pat_len) == 0)
                return TRUE;
        }
    }
    return FALSE;
}

static wchar_t* MatchListGetRule(PUNICODE_STRING s, wchar_t** list)
{
    if (!s || !s->Buffer || s->Length == 0)
        return 0;
    
    size_t s_len = s->Length / sizeof(WCHAR);
    for (SIZE_T i = 0; list[i]; ++i) {
        wchar_t* pat = list[i];
        size_t pat_len = wcslen(pat);
        if (wcschr(pat, L'*') || wcschr(pat, L'?')) {
            if (WildMatchN(s->Buffer, s_len, pat))
                return pat;
        }
        else {
            if (s_len == pat_len && _wcsnicmp(s->Buffer, pat, pat_len) == 0)
                return pat;
            if (s_len > pat_len && _wcsnicmp(s->Buffer + s_len - pat_len, pat, pat_len) == 0)
                return pat;
            if (s_len > pat_len && _wcsnicmp(s->Buffer, pat, pat_len) == 0)
                return pat;
        }
    }
    return 0;
}

static __forceinline BOOLEAN USOK(PUNICODE_STRING s)
{
    return s && s->Buffer && s->Length;
}

static BOOLEAN StrStrIW(const wchar_t* s, const wchar_t* sub)
{
    if (!s || !sub)
        return FALSE;
    
    SIZE_T n = wcslen(s), m = wcslen(sub);
    if (m == 0 || n < m)
        return FALSE;
    
    for (SIZE_T i = 0; i + m <= n; i++) {
        SIZE_T j = 0;
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

static BOOLEAN EndsWithNameUS(PUNICODE_STRING s, const wchar_t* name)
{
    if (!USOK(s) || !name)
        return FALSE;
    SIZE_T n = s->Length / sizeof(WCHAR);
    SIZE_T m = wcslen(name);
    if (n < m)
        return FALSE;
    return _wcsnicmp(s->Buffer + (n - m), name, m) == 0;
}

BOOLEAN IsRegistryBlock(PUNICODE_STRING key, PUNICODE_STRING valueName, PUNICODE_STRING exe)
{
    if (USOK(key)) {
        size_t klen0 = key->Length / sizeof(WCHAR);
        if (WildMatchN(key->Buffer, klen0, L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\**"))
            return FALSE;
    }
    if (USOK(exe)) {
        if (IsWhitelist(exe))
            return FALSE;
    }
    if (USOK(exe) && USOK(key)) {
        size_t elen = exe->Length / sizeof(WCHAR);
        size_t klen = key->Length / sizeof(WCHAR);

        if (((elen >= 12 && _wcsnicmp(exe->Buffer + elen - 12, L"services.exe", 12) == 0) ||
            (elen >= 11 && _wcsnicmp(exe->Buffer + elen - 11, L"svchost.exe", 11) == 0) ||
            (elen >= 6 && _wcsnicmp(exe->Buffer + elen - 6, L"sc.exe", 6) == 0))) {
            if (WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\SYSTEM\\CurrentControlSet\\Services\\**"))
                return FALSE;
        }
        if ((elen >= 14 && _wcsnicmp(exe->Buffer + elen - 14, L"powershell.exe", 14) == 0) ||
            (elen >= 8 && _wcsnicmp(exe->Buffer + elen - 8, L"pwsh.exe", 8) == 0)) {
            if (WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\CurrentVersion\\Internet Settings\\ZoneMap") ||
                WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\CurrentVersion\\Internet Settings\\ZoneMap\\**") ||
                WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\CurrentVersion\\Notifications\\Data") ||
                WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\CurrentVersion\\Notifications\\Data\\**"))
                return FALSE;
        }
        if ((elen >= 11 && _wcsnicmp(exe->Buffer + elen - 11, L"msiexec.exe", 11) == 0) ||
            (elen >= 20 && _wcsnicmp(exe->Buffer + elen - 20, L"TrustedInstaller.exe", 20) == 0)) {
            if (WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\CurrentVersion\\Installer\\**") ||
                WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\CurrentVersion\\Uninstall\\**") ||
                WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\SYSTEM\\CurrentControlSet\\Services\\**"))
                return FALSE;
        }
        if (elen >= 12 && _wcsnicmp(exe->Buffer + elen - 12, L"schtasks.exe", 12) == 0) {
            if (WildMatchN(key->Buffer, klen, L"\\REGISTRY\\**\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\**"))
                return FALSE;
        }
    }
    if (USOK(key)) {
        if (MatchBlockReg(key))
            return TRUE;
    }
    if (USOK(valueName)) {
        SIZE_T n = valueName->Length / sizeof(WCHAR);
        for (SIZE_T i = 0; i < (SIZE_T)-1 && g_BlockReg[i]; ++i) {
            wchar_t* pat = g_BlockReg[i];
            if (wcschr(pat, L'\\') || wcschr(pat, L'*') || wcschr(pat, L'?'))
                continue;
            size_t m = wcslen(pat);
            if (n == m && _wcsnicmp(valueName->Buffer, pat, m) == 0)
                return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN GetProcessImagePathByPid(HANDLE pid, PUNICODE_STRING ProcessImagePath)
{
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status))
        return FALSE;
    
    HANDLE h = NULL;
    status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL, PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, KernelMode, &h);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return FALSE;
    }
    ULONG len = 0;
    status = ZwQueryInformationProcess(h, ProcessImageFileName, NULL, 0, &len);
    if (status != STATUS_INFO_LENGTH_MISMATCH || len == 0) {
        ZwClose(h);
        ObDereferenceObject(process);
        return FALSE;
    }
    PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, len, 'iPgN');
    if (!buf) {
        ZwClose(h);
        ObDereferenceObject(process);
        return FALSE;
    }
    status = ZwQueryInformationProcess(h, ProcessImageFileName, buf, len, &len);
    if (NT_SUCCESS(status)) {
        PUNICODE_STRING image = (PUNICODE_STRING)buf;
        if (image->Buffer && image->Length > 0 && ProcessImagePath->MaximumLength >= image->Length + sizeof(WCHAR)) {
            RtlCopyMemory(ProcessImagePath->Buffer, image->Buffer, image->Length);
            ProcessImagePath->Length = image->Length;
            ProcessImagePath->Buffer[image->Length / sizeof(WCHAR)] = 0;
            ExFreePool2(buf, 'iPgN', NULL, 0);
            ZwClose(h);
            ObDereferenceObject(process);
            return TRUE;
        }
    }
    ExFreePool2(buf, 'iPgN', NULL, 0);
    ZwClose(h);
    ObDereferenceObject(process);
    return FALSE;
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
    if (!USOK(s))
        return FALSE;
    SIZE_T n = s->Length / sizeof(WCHAR);
    for (SIZE_T i = 0; g_Blocksuffix[i]; ++i) {
        wchar_t* ext = g_Blocksuffix[i];
        SIZE_T m = wcslen(ext);
        if (n >= m && _wcsnicmp(s->Buffer + (n - m), ext, m) == 0)
            return TRUE;
    }
    return FALSE;
}

BOOLEAN MatchRemoteSuspectBin(PUNICODE_STRING img)
{
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
    if (USOK(img) && EndsWithNameUS(img, L"regsvr32.exe")) {
        BOOLEAN need = FALSE, http = FALSE;
        for (SIZE_T i = 0; g_RemoteCmdRegsvr32Need[i]; ++i)
            if (StrStrIW(s, g_RemoteCmdRegsvr32Need[i])) { 
                need = TRUE;
                break;
            }
        for (SIZE_T i = 0; g_RemoteCmdIndicatorsHttp[i]; ++i)
            if (StrStrIW(s, g_RemoteCmdIndicatorsHttp[i])) {
                http = TRUE;
                break; 
            }
        if (need && http)
            return TRUE;
    }

    if (USOK(img) && EndsWithNameUS(img, L"mshta.exe")) {
        for (SIZE_T i = 0; g_RemoteCmdFromMshtaExe[i]; ++i)
            if (StrStrIW(s, g_RemoteCmdFromMshtaExe[i]))
                return TRUE;
    }
    return FALSE;
}

BOOLEAN MatchScreenCapModule(PUNICODE_STRING mod)
{
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
    BOOLEAN isClr = StrStrIW(s, L"\\clr.dll") || StrStrIW(s, L"\\mscorwks.dll");
    
    if (!isClr)
        return FALSE;
    if (!StrStrIW(s, L"\\Windows\\Microsoft.NET\\"))
        return TRUE;
    if (!StrStrIW(s, L"\\Framework\\") && !StrStrIW(s, L"\\Framework64\\"))
        return TRUE;
    return FALSE;
}
