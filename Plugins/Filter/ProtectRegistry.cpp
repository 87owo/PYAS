#include "DriverCommon.h"

LARGE_INTEGER Cookie;

static NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2) {
    UNREFERENCED_PARAMETER(CallbackContext);

    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_SUCCESS;

    REG_NOTIFY_CLASS Class = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    if (Class == RegNtPreSetValueKey || Class == RegNtPreDeleteKey || Class == RegNtPreCreateKey) {
        REG_SET_VALUE_KEY_INFORMATION* Info = (REG_SET_VALUE_KEY_INFORMATION*)Argument2;
        PCUNICODE_STRING KeyName = NULL;

        if (!NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&Cookie, Info->Object, NULL, &KeyName, 0))) {
            return STATUS_SUCCESS;
        }

        if (KeyName && KeyName->Buffer) {
            if (CheckRegistryRule(KeyName)) {
                HANDLE Pid = PsGetCurrentProcessId();

                if (WildcardMatch(L"*\\MACHINE\\SAM\\*", KeyName->Buffer, KeyName->Length) ||
                    WildcardMatch(L"*\\MACHINE\\SECURITY\\*", KeyName->Buffer, KeyName->Length)) {

                    if (!IsCriticalSystemProcess(Pid)) {
                        SendMessageToUser(3001, (ULONG)(ULONG_PTR)Pid, KeyName->Buffer, KeyName->Length);
                        CmCallbackReleaseKeyObjectIDEx(KeyName);
                        return STATUS_ACCESS_DENIED;
                    }
                }
                else {
                    if (!IsProcessTrusted(Pid)) {
                        if (!IsInstallerProcess(Pid)) {
                            SendMessageToUser(3001, (ULONG)(ULONG_PTR)Pid, KeyName->Buffer, KeyName->Length);
                            CmCallbackReleaseKeyObjectIDEx(KeyName);
                            return STATUS_ACCESS_DENIED;
                        }
                    }
                }
            }
        }

        if (KeyName) {
            CmCallbackReleaseKeyObjectIDEx(KeyName);
        }
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