#include "DriverCommon.h"

static LARGE_INTEGER Cookie;

static BOOLEAN IsBamRegistryPath(PCUNICODE_STRING KeyName) {
    if (!KeyName || !KeyName->Buffer) return FALSE;
    if (WildcardMatch(L"*\\Services\\bam\\*", KeyName->Buffer, KeyName->Length)) {
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN IsWriteAccess(ACCESS_MASK Access) {
    if (Access & (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK |
        DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE)) {
        return TRUE;
    }
    return FALSE;
}

static PWCHAR GetFullPath(PVOID RootObject, PUNICODE_STRING CompleteName, PULONG OutLength) {
    PWCHAR Buffer = NULL;
    ULONG TotalSize = 0;
    PCUNICODE_STRING RootName = NULL;
    BOOLEAN NeedFreeRootName = FALSE;

    if (RootObject) {
        NTSTATUS status = CmCallbackGetKeyObjectIDEx(&Cookie, RootObject, NULL, &RootName, 0);
        if (NT_SUCCESS(status) && RootName) {
            NeedFreeRootName = TRUE;
        }
    }

    ULONG RootLen = (RootName && RootName->Buffer) ? RootName->Length : 0;
    ULONG RelLen = (CompleteName && CompleteName->Buffer) ? CompleteName->Length : 0;

    TotalSize = RootLen + sizeof(WCHAR) + RelLen + sizeof(WCHAR);

    Buffer = (PWCHAR)PyasAllocate(TotalSize);
    if (!Buffer) {
        if (NeedFreeRootName) CmCallbackReleaseKeyObjectIDEx(RootName);
        return NULL;
    }

    RtlZeroMemory(Buffer, TotalSize);

    PWCHAR Current = Buffer;
    if (RootLen > 0) {
        RtlCopyMemory(Current, RootName->Buffer, RootLen);
        Current += (RootLen / sizeof(WCHAR));
        if (Current > Buffer && *(Current - 1) != L'\\') {
            *Current = L'\\';
            Current++;
        }
    }

    if (RelLen > 0) {
        if (RootLen > 0 && CompleteName->Buffer[0] == L'\\') {
            RtlCopyMemory(Current, CompleteName->Buffer + 1, RelLen - sizeof(WCHAR));
        }
        else {
            RtlCopyMemory(Current, CompleteName->Buffer, RelLen);
        }
    }

    if (NeedFreeRootName) CmCallbackReleaseKeyObjectIDEx(RootName);

    if (OutLength) *OutLength = (ULONG)wcslen(Buffer) * sizeof(WCHAR);
    return Buffer;
}

static NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2) {
    UNREFERENCED_PARAMETER(CallbackContext);

    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_SUCCESS;

    REG_NOTIFY_CLASS Class = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    NTSTATUS status = STATUS_SUCCESS;

    if (Class == RegNtPreCreateKey || Class == RegNtPreOpenKey || Class == RegNtPreOpenKeyEx) {
        PVOID RootObject = NULL;
        PUNICODE_STRING CompleteName = NULL;
        ACCESS_MASK DesiredAccess = 0;

        if (Class == RegNtPreCreateKey) {
            REG_CREATE_KEY_INFORMATION* Info = (REG_CREATE_KEY_INFORMATION*)Argument2;
            RootObject = Info->RootObject;
            CompleteName = Info->CompleteName;
            DesiredAccess = Info->DesiredAccess;
        }
        else {
            REG_OPEN_KEY_INFORMATION* Info = (REG_OPEN_KEY_INFORMATION*)Argument2;
            RootObject = Info->RootObject;
            CompleteName = Info->CompleteName;
            DesiredAccess = Info->DesiredAccess;
        }

        if (!IsWriteAccess(DesiredAccess)) {
            return STATUS_SUCCESS;
        }

        ULONG PathLen = 0;
        PWCHAR FullPathBuffer = GetFullPath(RootObject, CompleteName, &PathLen);

        if (FullPathBuffer) {
            UNICODE_STRING FullPath;
            RtlInitUnicodeString(&FullPath, FullPathBuffer);

            if (CheckRegistryRule(&FullPath)) {
                HANDLE Pid = PsGetCurrentProcessId();
                if (!IsProcessTrusted(Pid)) {
                    SendMessageToUser(3001, (ULONG)(ULONG_PTR)Pid, FullPath.Buffer, FullPath.Length);
                    status = STATUS_ACCESS_DENIED;
                }
            }
            PyasFree(FullPathBuffer);
        }
        return status;
    }

    if (Class == RegNtPreDeleteKey) {
        REG_DELETE_KEY_INFORMATION* Info = (REG_DELETE_KEY_INFORMATION*)Argument2;
        PCUNICODE_STRING KeyName = NULL;

        if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&Cookie, Info->Object, NULL, &KeyName, 0))) {
            if (KeyName) {
                if (CheckRegistryRule(KeyName)) {
                    HANDLE Pid = PsGetCurrentProcessId();
                    if (!IsProcessTrusted(Pid)) {
                        SendMessageToUser(3001, (ULONG)(ULONG_PTR)Pid, KeyName->Buffer, KeyName->Length);
                        status = STATUS_ACCESS_DENIED;
                    }
                }
                CmCallbackReleaseKeyObjectIDEx(KeyName);
            }
        }
        return status;
    }

    if (Class == RegNtPreSetValueKey) {
        REG_SET_VALUE_KEY_INFORMATION* Info = (REG_SET_VALUE_KEY_INFORMATION*)Argument2;
        PCUNICODE_STRING KeyName = NULL;

        if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&Cookie, Info->Object, NULL, &KeyName, 0))) {
            if (KeyName && KeyName->Buffer) {
                if (!IsBamRegistryPath(KeyName)) {
                    ULONG FullSize = KeyName->Length + sizeof(WCHAR) +
                        (Info->ValueName ? Info->ValueName->Length : 0) +
                        sizeof(WCHAR);

                    PWCHAR Buffer = (PWCHAR)PyasAllocate(FullSize);
                    if (Buffer) {
                        UNICODE_STRING FullPath;
                        FullPath.Buffer = Buffer;
                        FullPath.Length = 0;
                        FullPath.MaximumLength = (USHORT)FullSize;

                        RtlCopyUnicodeString(&FullPath, KeyName);

                        if (Info->ValueName && Info->ValueName->Length > 0) {
                            if (FullPath.Length > 0 && FullPath.Buffer[(FullPath.Length / sizeof(WCHAR)) - 1] != L'\\') {
                                RtlAppendUnicodeToString(&FullPath, L"\\");
                            }
                            RtlAppendUnicodeStringToString(&FullPath, Info->ValueName);
                        }

                        if (CheckRegistryRule(&FullPath)) {
                            HANDLE Pid = PsGetCurrentProcessId();
                            if (!IsProcessTrusted(Pid)) {
                                SendMessageToUser(3001, (ULONG)(ULONG_PTR)Pid, FullPath.Buffer, FullPath.Length);
                                status = STATUS_ACCESS_DENIED;
                            }
                        }
                        PyasFree(Buffer);
                    }
                }
                CmCallbackReleaseKeyObjectIDEx(KeyName);
            }
        }
        return status;
    }

    if (Class == RegNtPreDeleteValueKey) {
        REG_DELETE_VALUE_KEY_INFORMATION* Info = (REG_DELETE_VALUE_KEY_INFORMATION*)Argument2;
        PCUNICODE_STRING KeyName = NULL;

        if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&Cookie, Info->Object, NULL, &KeyName, 0))) {
            if (KeyName && KeyName->Buffer) {
                if (!IsBamRegistryPath(KeyName)) {
                    ULONG FullSize = KeyName->Length + sizeof(WCHAR) +
                        (Info->ValueName ? Info->ValueName->Length : 0) +
                        sizeof(WCHAR);

                    PWCHAR Buffer = (PWCHAR)PyasAllocate(FullSize);
                    if (Buffer) {
                        UNICODE_STRING FullPath;
                        FullPath.Buffer = Buffer;
                        FullPath.Length = 0;
                        FullPath.MaximumLength = (USHORT)FullSize;

                        RtlCopyUnicodeString(&FullPath, KeyName);

                        if (Info->ValueName && Info->ValueName->Length > 0) {
                            if (FullPath.Length > 0 && FullPath.Buffer[(FullPath.Length / sizeof(WCHAR)) - 1] != L'\\') {
                                RtlAppendUnicodeToString(&FullPath, L"\\");
                            }
                            RtlAppendUnicodeStringToString(&FullPath, Info->ValueName);
                        }

                        if (CheckRegistryRule(&FullPath)) {
                            HANDLE Pid = PsGetCurrentProcessId();
                            if (!IsProcessTrusted(Pid)) {
                                SendMessageToUser(3001, (ULONG)(ULONG_PTR)Pid, FullPath.Buffer, FullPath.Length);
                                status = STATUS_ACCESS_DENIED;
                            }
                        }
                        PyasFree(Buffer);
                    }
                }
                CmCallbackReleaseKeyObjectIDEx(KeyName);
            }
        }
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS InitializeRegistryProtection(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING Altitude;
    RtlInitUnicodeString(&Altitude, L"320000");
    return CmRegisterCallbackEx(RegistryCallback, &Altitude, DriverObject, NULL, &Cookie, NULL);
}

VOID UninitializeRegistryProtection() {
    if (Cookie.QuadPart != 0) {
        CmUnRegisterCallback(Cookie);
        Cookie.QuadPart = 0;
    }
}