#include "DriverCommon.h"

VOID ProcessNotifyCallbackEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    if (CreateInfo != NULL) {
        if (KeGetCurrentIrql() > APC_LEVEL) return;

        HANDLE ParentId = CreateInfo->CreatingThreadId.UniqueProcess;
        if (!ParentId) return;

        ULONG RuleCode = 0;
        if (EvaluateProcessRule(ParentId, CreateInfo->ImageFileName, CreateInfo->CommandLine, &RuleCode)) {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            if (CreateInfo->ImageFileName) {
                SendMessageToUser(RuleCode, (ULONG)(ULONG_PTR)ParentId, CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
            }
        }
    }
}