#include <ntifs.h>
#include <ntstrsafe.h>
#include "DriverEntry.h"

extern PDEVICE_OBJECT g_ControlDeviceObject;

typedef struct _PIPE_LOG_CTX {
    PIO_WORKITEM Item;
    SIZE_T Len;
    PCHAR Buf;
}PIPE_LOG_CTX, * PPIPE_LOG_CTX;

static VOID PipeLogWork(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PPIPE_LOG_CTX ctx = (PPIPE_LOG_CTX)Context;
    HANDLE h = NULL;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa = { 0 };
    IO_STATUS_BLOCK iosb;
    
    RtlInitUnicodeString(&name, PIPE_NAME);
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (NT_SUCCESS(ZwCreateFile(&h, FILE_GENERIC_WRITE, &oa, &iosb, NULL, 0, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0))) {
        ZwWriteFile(h, NULL, NULL, NULL, &iosb, ctx->Buf, (ULONG)(ctx->Len > 0xFFFFFFFF ? 0xFFFFFFFF : ctx->Len), NULL, NULL);
        ZwClose(h);
    }
    IoFreeWorkItem(ctx->Item);
    ExFreePool2(ctx->Buf, 'golP', NULL, 0);
    ExFreePool2(ctx, 'golP', NULL, 0);
    
    if (InterlockedDecrement(&g_LogWorkCount) == 0) {
        KeSetEvent(&g_LogDrainEvent, IO_NO_INCREMENT, FALSE);
    }
}

VOID SendPipeLog(PCSTR msg, SIZE_T len)
{
    if (!msg || len == 0)
        return;
    if (!g_ControlDeviceObject)
        return;
    if (g_Unloading)
        return;
    PPIPE_LOG_CTX ctx = (PPIPE_LOG_CTX)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PIPE_LOG_CTX), 'golP');
    if (!ctx)
        return;
    ctx->Len = len;
    ctx->Buf = (PCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, ctx->Len, 'golP');
    if (!ctx->Buf) {
        ExFreePool2(ctx, 'golP', NULL, 0);
        return;
    }
    RtlCopyMemory(ctx->Buf, msg, ctx->Len);
    ctx->Item = IoAllocateWorkItem(g_ControlDeviceObject);
    if (!ctx->Item) {
        ExFreePool2(ctx->Buf, 'golP', NULL, 0);
        ExFreePool2(ctx, 'golP', NULL, 0);
        return;
    }
    InterlockedIncrement(&g_LogWorkCount);
    IoQueueWorkItem(ctx->Item, PipeLogWork, DelayedWorkQueue, ctx);
}

VOID LogAnsi3(PCSTR tag, ULONG upid, PUNICODE_STRING s1, PUNICODE_STRING s2)
{
    ANSI_STRING a1 = { 0 }, a2 = { 0 };
    CHAR buf[1024] = { 0 };

    if (s1)
        RtlUnicodeStringToAnsiString(&a1, s1, TRUE);
    if (s2)
        RtlUnicodeStringToAnsiString(&a2, s2, TRUE);

    RtlStringCchPrintfA(buf, RTL_NUMBER_OF(buf), "%s | %u | %s | %s", tag, upid, a1.Buffer ? a1.Buffer : "",  a2.Buffer ? a2.Buffer : "");
    SendPipeLog(buf, strlen(buf));

    RtlFreeAnsiString(&a1);
    RtlFreeAnsiString(&a2);
}