#pragma once
#include <fltKernel.h>
#include <ntddk.h>      
#include <ntdddisk.h>   
#include <ntddscsi.h> 
#include <ntstrsafe.h>

constexpr auto PYAS_PORT_NAME = L"\\PYAS_Output_Pipe";
constexpr auto MAX_PATH_LEN = 1024;
constexpr auto PYAS_POOL_TAG = 'SAYP';

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                  (0x0001)
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD              (0x0002)
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION               (0x0008)
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ                    (0x0010)
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE                   (0x0020)
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE                 (0x0040)
#endif
#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS             (0x0080)
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION            (0x0200)
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION          (0x0400)
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME             (0x0800)
#endif
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA (0x0100)
#endif

#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED 0x0000000000000040UI64
#endif

#ifndef FSCTL_MANAGE_BYPASS_IO
#define FSCTL_MANAGE_BYPASS_IO CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 188, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef enum _FS_BPIO_OPERATIONS {
    FS_BPIO_OP_ENABLE = 1,
    FS_BPIO_OP_DISABLE = 2,
    FS_BPIO_OP_QUERY = 3,
    FS_BPIO_OP_VOLUME_STACK_PAUSE = 4,
    FS_BPIO_OP_VOLUME_STACK_RESUME = 5,
    FS_BPIO_OP_STREAM_PAUSE = 6,
    FS_BPIO_OP_STREAM_RESUME = 7,
    FS_BPIO_OP_GET_INFO = 8
} FS_BPIO_OPERATIONS;

typedef struct _FS_BPIO_INPUT {
    FS_BPIO_OPERATIONS Operation;
    ULONG InFlags;
    ULONGLONG Reserved1;
    ULONGLONG Reserved2;
} FS_BPIO_INPUT, * PFS_BPIO_INPUT;

typedef struct _FS_BPIO_OUTPUT {
    FS_BPIO_OPERATIONS Operation;
    ULONG OutFlags;
    ULONGLONG Reserved1;
    ULONGLONG Reserved2;
    NTSTATUS Status;
} FS_BPIO_OUTPUT, * PFS_BPIO_OUTPUT;

#endif

typedef struct _PYAS_MESSAGE {
    ULONG MessageCode;
    ULONG ProcessId;
    WCHAR Path[MAX_PATH_LEN];
} PYAS_MESSAGE, * PPYAS_MESSAGE;

typedef struct _DRIVER_DATA {
    PDRIVER_OBJECT DriverObject;
    PFLT_FILTER FilterHandle;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    PEPROCESS PyasProcess;
    ULONG PyasPid;
    LARGE_INTEGER Cookie;
    FAST_MUTEX PortMutex;
    FAST_MUTEX TrackerMutex;
    EX_RUNDOWN_REF PortRundown;
} DRIVER_DATA, * PDRIVER_DATA;

typedef struct _RULE_NODE {
    struct _RULE_NODE* Next;
    UNICODE_STRING Pattern;
} RULE_NODE, * PRULE_NODE;

extern DRIVER_DATA GlobalData;

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_PreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_PreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_FileSystemControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_SetSecurity(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectBoot_PreDeviceControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

NTSTATUS InitializeProcessProtection();
VOID UninitializeProcessProtection();
NTSTATUS InitializeRegistryProtection(PDRIVER_OBJECT DriverObject);
VOID UninitializeRegistryProtection();

NTSTATUS LoadRulesFromDisk(PUNICODE_STRING RegistryPath);
VOID UnloadRules();

VOID ImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);

NTSTATUS GetProcessImageName(HANDLE ProcessId, PUNICODE_STRING* ImageName);

BOOLEAN IsProcessTrusted(HANDLE ProcessId);
BOOLEAN IsCriticalSystemProcess(HANDLE ProcessId);
BOOLEAN IsTargetProtected(HANDLE ProcessId);
BOOLEAN IsInstallerProcess(HANDLE ProcessId);
BOOLEAN WildcardMatch(PCWSTR Pattern, PCWSTR String, USHORT StringLengthBytes);

BOOLEAN CheckRegistryRule(PCUNICODE_STRING KeyName);
BOOLEAN CheckFileExtensionRule(PCUNICODE_STRING FileName);
BOOLEAN CheckProtectedPathRule(PCUNICODE_STRING FileName);
BOOLEAN CheckRansomActivity(HANDLE ProcessId, PUNICODE_STRING FileName, PVOID WriteBuffer, ULONG WriteLength, BOOLEAN IsWrite);

NTSTATUS SendMessageToUser(ULONG Code, ULONG Pid, PWCHAR Path, USHORT PathSize);

FORCEINLINE PVOID PyasAllocate(SIZE_T Size) {
#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, PYAS_POOL_TAG);
#else
    PVOID Buffer = ExAllocatePoolWithTag(NonPagedPoolNx, Size, PYAS_POOL_TAG);
    if (Buffer) RtlZeroMemory(Buffer, Size);
    return Buffer;
#endif
}

FORCEINLINE VOID PyasFree(PVOID Ptr) {
    if (Ptr) ExFreePoolWithTag(Ptr, PYAS_POOL_TAG);
}