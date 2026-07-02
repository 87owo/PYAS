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
#define PROCESS_SET_QUOTA                  (0x0100)
#endif
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE                   (0x0001)
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME              (0x0002)
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT                 (0x0010)
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION             (0x0020)
#endif
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN            (0x0080)
#endif
#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED                0x0000000000000040UI64
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

typedef struct _PYAS_USER_MESSAGE {
    ULONG Command;
    WCHAR Path[MAX_PATH_LEN];
} PYAS_USER_MESSAGE, * PPYAS_USER_MESSAGE;

typedef struct _DRIVER_DATA {
    PDRIVER_OBJECT DriverObject;
    PFLT_FILTER FilterHandle;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    PEPROCESS PyasProcess;
    ULONG PyasPid;
    LARGE_INTEGER Cookie;
    KSPIN_LOCK PortMutex;
    KSPIN_LOCK TrackerMutex;
    KSPIN_LOCK PidLock;
    BOOLEAN Initialized;
    EX_RUNDOWN_REF PortRundown;
    PVOID ObRegistrationHandle;
} DRIVER_DATA, * PDRIVER_DATA;

typedef struct _RULE_NODE {
    struct _RULE_NODE* Next;
    UNICODE_STRING Pattern;
} RULE_NODE, * PRULE_NODE;

typedef enum _RULE_CATEGORY {
    RuleCategoryProcess,
    RuleCategoryFile,
    RuleCategoryRegistry,
    RuleCategoryDevice,
    RuleCategoryMemory,
    RuleCategoryThread,
    RuleCategoryUnknown
} RULE_CATEGORY;

#define OP_WRITE         0x01
#define OP_DELETE        0x02
#define OP_CREATE        0x04
#define OP_EXECUTE       0x08
#define OP_RENAME        0x10
#define OP_IOCTL         0x20
#define OP_VM_READ       0x40
#define OP_VM_WRITE      0x80

BOOLEAN EvaluateDeviceRule(HANDLE ProcessId, PULONG OutCode);

typedef struct _DYNAMIC_RULE {
    ULONG Code;
    RULE_CATEGORY Category;
    ULONG Operations;

    PRULE_NODE Initiator;
    PRULE_NODE InitiatorExclude;
    PRULE_NODE Target;
    PRULE_NODE TargetExclude;
    PRULE_NODE CommandLine;
    PRULE_NODE Extensions;

    ULONG Threshold;
    ULONG TimeWindow;

    struct _DYNAMIC_RULE* Next;
} DYNAMIC_RULE, * PDYNAMIC_RULE;

extern DRIVER_DATA GlobalData;

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_PreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_PreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_FileSystemControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_SetSecurity(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectBoot_PreDeviceControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

NTSTATUS InitializeRegistryProtection(PDRIVER_OBJECT DriverObject);
VOID UninitializeRegistryProtection();

NTSTATUS InitializeMemoryProtection(PDRIVER_OBJECT DriverObject);
VOID UninitializeMemoryProtection();

NTSTATUS LoadRulesFromDisk(PUNICODE_STRING RegistryPath);
VOID UnloadRules();

VOID InitializeRulesEngine();
VOID UninitializeRulesEngine();

VOID AddDynamicWhitelist(PUNICODE_STRING RuleStr);
VOID RemoveDynamicWhitelist(PUNICODE_STRING RuleStr);

NTSTATUS LoadRuleFile(PCUNICODE_STRING FilePath);
VOID ClearDynamicRules();

VOID ProcessNotifyCallbackEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
NTSTATUS GetProcessImageName(HANDLE ProcessId, PUNICODE_STRING* ImageName);

ULONG SafeGetPyasPid();
VOID SafeSetPyasPid(ULONG Pid);

BOOLEAN IsProcessTrusted(HANDLE ProcessId);
BOOLEAN WildcardMatch(PCWSTR Pattern, PCWSTR String, USHORT StringLengthBytes);

BOOLEAN EvaluateProcessRule(HANDLE ProcessId, PCUNICODE_STRING TargetPath, PCUNICODE_STRING CommandLine, PULONG OutCode);
BOOLEAN EvaluateFileRule(HANDLE ProcessId, PCUNICODE_STRING TargetPath, ULONG Operation, PVOID WriteBuffer, ULONG WriteLength, PULONG OutCode);
BOOLEAN EvaluateRegistryRule(HANDLE ProcessId, PCUNICODE_STRING KeyName, ULONG Operation, PULONG OutCode);
BOOLEAN EvaluateMemoryRule(HANDLE SourcePid, HANDLE TargetPid, ULONG Operation, PULONG OutCode);
BOOLEAN EvaluateThreadRule(HANDLE SourcePid, HANDLE TargetPid, PVOID StartAddress, PULONG OutCode);

NTSTATUS SendMessageToUser(ULONG Code, ULONG Pid, PWCHAR Path, USHORT PathSize);

FORCEINLINE PVOID PyasAllocate(SIZE_T Size) {
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, PYAS_POOL_TAG);
}

FORCEINLINE VOID PyasFree(PVOID Ptr) {
    if (Ptr) ExFreePoolWithTag(Ptr, PYAS_POOL_TAG);
}