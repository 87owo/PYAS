#include <ntifs.h>
#include "DriverEntry.h"
#include "ProtectMatch.h"

static BOOLEAN QueryRegPathFromObject(PVOID KeyObject, PUNICODE_STRING OutPath, POBJECT_NAME_INFORMATION* OutInfo)
{
    ULONG len = 0;
    NTSTATUS s = ObQueryNameString(KeyObject, NULL, 0, &len);
    if (s != STATUS_INFO_LENGTH_MISMATCH)
        return FALSE;

    POBJECT_NAME_INFORMATION p = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, len, 'rgeR');
    if (!p)
        return FALSE;

    s = ObQueryNameString(KeyObject, p, len, &len);
    if (!NT_SUCCESS(s) || !p->Name.Buffer || p->Name.Length == 0) {
        ExFreePool2(p, 'rgeR', NULL, 0);
        return FALSE;
    }
    *OutInfo = p;
    OutPath->Buffer = p->Name.Buffer;
    OutPath->Length = p->Name.Length;
    OutPath->MaximumLength = p->Name.Length;
    return TRUE;
}

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

NTSTATUS RegistryProtectCallback(PVOID ctx, PVOID arg1, PVOID arg2)
{
    UNREFERENCED_PARAMETER(ctx);
    if (g_Unloading)
        return STATUS_SUCCESS;
    if (!ExAcquireRundownProtection(&g_Rundown))
        return STATUS_SUCCESS;

    REG_NOTIFY_CLASS type = (REG_NOTIFY_CLASS)(ULONG_PTR)arg1;
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING checkReg = { 0 };
    POBJECT_NAME_INFORMATION nameInfo = NULL;

    UNICODE_STRING exe = { 0 };
    WCHAR exeBuf[260] = { 0 };
    exe.Buffer = exeBuf;
    exe.MaximumLength = sizeof(exeBuf);
    exe.Length = 0;

    HANDLE pid = PsGetCurrentProcessId();
    if (pid == (HANDLE)0 || pid == (HANDLE)4) {
        ExReleaseRundownProtection(&g_Rundown);
        return STATUS_SUCCESS;
    }
    PUNICODE_STRING valueName = NULL;
    BOOLEAN need_log = FALSE;
    BOOLEAN canQuery = (KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (type == RegNtPreSetValueKey) {
        PREG_SET_VALUE_KEY_INFORMATION s = (PREG_SET_VALUE_KEY_INFORMATION)arg2;
        valueName = s->ValueName;
        if (canQuery)
            QueryRegPathFromObject(s->Object, &checkReg, &nameInfo);
    }
    else if (type == RegNtPreDeleteValueKey) {
        PREG_DELETE_VALUE_KEY_INFORMATION d = (PREG_DELETE_VALUE_KEY_INFORMATION)arg2;
        valueName = d->ValueName;
        if (canQuery)
            QueryRegPathFromObject(d->Object, &checkReg, &nameInfo);
    }
    else if (type == RegNtPreDeleteKey) {
        PREG_DELETE_KEY_INFORMATION d = (PREG_DELETE_KEY_INFORMATION)arg2;
        if (canQuery)
            QueryRegPathFromObject(d->Object, &checkReg, &nameInfo);
    }
    else if (type == RegNtPreRenameKey) {
        PREG_RENAME_KEY_INFORMATION r = (PREG_RENAME_KEY_INFORMATION)arg2;
        if (canQuery)
            QueryRegPathFromObject(r->Object, &checkReg, &nameInfo);
    }
    else if (type == RegNtPreCreateKeyEx) {
        PREG_CREATE_KEY_INFORMATION c = (PREG_CREATE_KEY_INFORMATION)arg2;
        if (c->CompleteName)
            checkReg = *c->CompleteName;
    }
    else if (type == RegNtPreReplaceKey) {
        PREG_REPLACE_KEY_INFORMATION rk = (PREG_REPLACE_KEY_INFORMATION)arg2;
        if (canQuery)
            QueryRegPathFromObject(rk->Object, &checkReg, &nameInfo);
    }
    else if (type == RegNtPreSaveKey) {
        PREG_SAVE_KEY_INFORMATION sk = (PREG_SAVE_KEY_INFORMATION)arg2;
        if (canQuery)
            QueryRegPathFromObject(sk->Object, &checkReg, &nameInfo);
    }
    else if (type == RegNtPreRestoreKey) {
        PREG_RESTORE_KEY_INFORMATION res = (PREG_RESTORE_KEY_INFORMATION)arg2;
        if (canQuery)
            QueryRegPathFromObject(res->Object, &checkReg, &nameInfo);
    }
    else if (type == RegNtPreLoadKey) {
        PREG_LOAD_KEY_INFORMATION lk = (PREG_LOAD_KEY_INFORMATION)arg2;
        if (lk->KeyName)
            checkReg = *lk->KeyName;
    }

    if (checkReg.Buffer || (valueName && valueName->Buffer)) {
        if (canQuery)
            GetProcessImagePathByPid(pid, &exe);
        if (IsRegistryBlock(&checkReg, valueName, &exe)) {
            need_log = TRUE;
            status = STATUS_ACCESS_DENIED;
        }
    }
    if (nameInfo)
        ExFreePool2(nameInfo, 'rgeR', NULL, 0);
    if (need_log)
        LogAnsi3("REG_BLOCK", (ULONG)(ULONG_PTR)pid, &exe, &checkReg);
    ExReleaseRundownProtection(&g_Rundown);
    return status;
}
