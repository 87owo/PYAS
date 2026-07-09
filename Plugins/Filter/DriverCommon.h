#pragma once
#include <fltKernel.h>
#include <ntddk.h>      
#include <ntdddisk.h>   
#include <ntddscsi.h> 
#include <ntstrsafe.h>

constexpr auto PYAS_PORT_NAME = L"\\PYAS_Output_Pipe";
constexpr auto MAX_PATH_LEN = 1024;
constexpr auto PYAS_POOL_TAG = 'SAYP';
constexpr auto PYAS_OB_ALTITUDE = L"320000.4101";
constexpr auto PYAS_CONNECTION_MAGIC = 0x53415950;
constexpr auto PYAS_CONNECTION_VERSION = 1;

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
#ifndef THREAD_IMPERSONATE
#define THREAD_IMPERSONATE                 (0x0100)
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION        (0x0200)
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


typedef enum _PYAS_DRIVER_STATE {
    PyasDriverStateCold = 0,
    PyasDriverStateStarting = 1,
    PyasDriverStateRunning = 2,
    PyasDriverStateStopping = 3,
    PyasDriverStateStopRetry = 4,
    PyasDriverStateStopped = 5
} PYAS_DRIVER_STATE;

typedef struct _PYAS_MESSAGE {
    ULONG MessageCode;
    ULONG ProcessId;
    WCHAR Path[MAX_PATH_LEN];
} PYAS_MESSAGE, * PPYAS_MESSAGE;

typedef enum _PYAS_COMMAND {
    PyasCommandAddWhitelist = 1,
    PyasCommandRemoveWhitelist = 2,
    PyasCommandLoadRuleFile = 3,
    PyasCommandClearRules = 4,
    PyasCommandAuthorizeUnload = 5,
    PyasCommandRevokeUnload = 6,
    PyasCommandQueryState = 7
} PYAS_COMMAND;

typedef struct _PYAS_USER_MESSAGE {
    ULONG Command;
    WCHAR Path[MAX_PATH_LEN];
} PYAS_USER_MESSAGE, * PPYAS_USER_MESSAGE;

typedef struct _PYAS_CONNECTION_CONTEXT {
    ULONG Size;
    ULONG Version;
    ULONG Magic;
    ULONG ProcessId;
} PYAS_CONNECTION_CONTEXT, * PPYAS_CONNECTION_CONTEXT;

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
    volatile LONG DriverState;
    volatile LONG UnloadAuthorized;
    volatile LONG PortStopping;
    volatile LONG ClientCloseActive;
    EX_RUNDOWN_REF PortRundown;
    KEVENT CleanupCompleteEvent;
    PVOID ObRegistrationHandle;
    UNICODE_STRING ClientImagePath;
    WCHAR ClientImagePathBuffer[MAX_PATH_LEN];
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

#define OP_WRITE                   0x00000001
#define OP_DELETE                  0x00000002
#define OP_CREATE                  0x00000004
#define OP_EXECUTE                 0x00000008
#define OP_RENAME                  0x00000010
#define OP_IOCTL                   0x00000020
#define OP_VM_READ                 0x00000040
#define OP_VM_WRITE                0x00000080
#define OP_TERMINATE               0x00000100
#define OP_SUSPEND_RESUME          0x00000200
#define OP_DUP_HANDLE              0x00000400
#define OP_SET_INFORMATION         0x00000800
#define OP_VM_OPERATION            0x00001000
#define OP_CREATE_THREAD           0x00002000
#define OP_THREAD_SET_CONTEXT      0x00004000
#define OP_THREAD_SET_TOKEN        0x00008000
#define OP_CREATE_PROCESS          0x00010000
#define OP_IMAGE_LOAD              0x00020000
#define OP_IMPERSONATE             0x00040000

#define PYAS_HANDLE_CREATE         0x00000001
#define PYAS_HANDLE_DUPLICATE      0x00000002

#define PYAS_OBJECT_PROCESS        0x00000001
#define PYAS_OBJECT_THREAD         0x00000002

#define PYAS_MEMORY_PRIVATE        0x00000001
#define PYAS_MEMORY_MAPPED         0x00000002
#define PYAS_MEMORY_IMAGE          0x00000004

#define PYAS_PROTECT_EXECUTE       0x00000001
#define PYAS_PROTECT_EXECUTE_WRITE 0x00000002

typedef enum _RULE_TRI_STATE {
    RuleTriAny = 0,
    RuleTriTrue = 1,
    RuleTriFalse = 2
} RULE_TRI_STATE;

typedef enum _RULE_OPERATION_MATCH {
    RuleOperationAny = 0,
    RuleOperationAll = 1
} RULE_OPERATION_MATCH;

typedef struct _DYNAMIC_RULE {
    ULONG Code;
    BOOLEAN Kill;
    ULONG Priority;
    RULE_CATEGORY Category;
    ULONG Operations;
    RULE_OPERATION_MATCH OperationMatch;
    BOOLEAN Invalid;

    PRULE_NODE Initiator;
    PRULE_NODE InitiatorExclude;
    PRULE_NODE InitiatorParent;
    PRULE_NODE InitiatorParentExclude;
    PRULE_NODE InitiatorProcessTree;
    PRULE_NODE InitiatorProcessTreeExclude;
    PRULE_NODE Target;
    PRULE_NODE TargetExclude;
    PRULE_NODE TargetProcessTree;
    PRULE_NODE TargetProcessTreeExclude;
    PRULE_NODE Creator;
    PRULE_NODE CreatorExclude;
    PRULE_NODE Parent;
    PRULE_NODE ParentExclude;
    PRULE_NODE CommandLine;
    PRULE_NODE CommandLineExclude;
    PRULE_NODE Extensions;

    ULONG HandleTypes;
    ULONG ObjectTypes;
    ULONG MinimumRiskScore;
    ULONG MaximumRiskScore;
    ULONG ThreadMemoryTypes;
    ULONG ThreadMemoryProtections;
    ULONGLONG MinimumRegionSize;
    ULONGLONG MaximumRegionSize;
    RULE_TRI_STATE ParentMismatch;
    RULE_TRI_STATE FileOpenNameAvailable;
    RULE_TRI_STATE SubsystemProcess;

    ULONG Threshold;
    ULONG TimeWindow;

    struct _DYNAMIC_RULE* Next;
} DYNAMIC_RULE, * PDYNAMIC_RULE;

BOOLEAN EvaluateDeviceRule(HANDLE ProcessId, PULONG OutCode, PBOOLEAN OutKill);

extern DRIVER_DATA GlobalData;

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_PreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_PreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_FileSystemControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_SetSecurity(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectBoot_PreDeviceControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

NTSTATUS InitializeRegistryProtection(PDRIVER_OBJECT DriverObject);
NTSTATUS UninitializeRegistryProtection();

NTSTATUS InitializeProcessProtection();
NTSTATUS UninitializeProcessProtection();
BOOLEAN GetProcessRelation(HANDLE ProcessId, PHANDLE ParentProcessId, PHANDLE CreatorProcessId);

NTSTATUS InitializeMemoryProtection(PDRIVER_OBJECT DriverObject);
NTSTATUS UninitializeMemoryProtection(BOOLEAN WaitWithoutTimeout);

NTSTATUS LoadRulesFromDisk(PUNICODE_STRING RegistryPath);
VOID UnloadRules();

NTSTATUS InitializeRulesEngine();
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

BOOLEAN EvaluateProcessCreateRule(
    HANDLE CreatorPid,
    HANDLE ParentPid,
    HANDLE ProcessId,
    PCUNICODE_STRING TargetPath,
    PCUNICODE_STRING CommandLine,
    BOOLEAN FileOpenNameAvailable,
    BOOLEAN IsSubsystemProcess,
    PULONG OutCode,
    PBOOLEAN OutKill
);
BOOLEAN EvaluateProcessAccessRule(
    HANDLE SourcePid,
    HANDLE TargetPid,
    ULONG RequestedOperations,
    ULONG HandleType,
    ULONG ObjectType,
    PULONG DeniedOperations,
    PULONG OutCode,
    PBOOLEAN OutKill
);
BOOLEAN EvaluateThreadRule(
    HANDLE SourcePid,
    HANDLE TargetPid,
    PVOID StartAddress,
    ULONG MemoryType,
    ULONG MemoryProtection,
    SIZE_T RegionSize,
    PULONG OutCode,
    PBOOLEAN OutKill
);
BOOLEAN EvaluateImageLoadRule(HANDLE ProcessId, PCUNICODE_STRING ImagePath, PIMAGE_INFO ImageInfo, PULONG OutCode, PBOOLEAN OutKill);
BOOLEAN EvaluateProcessRule(HANDLE ProcessId, PCUNICODE_STRING TargetPath, PCUNICODE_STRING CommandLine, PULONG OutCode, PBOOLEAN OutKill);
BOOLEAN EvaluateFileRule(HANDLE ProcessId, PCUNICODE_STRING TargetPath, ULONG Operation, PVOID WriteBuffer, ULONG WriteLength, PULONG OutCode, PBOOLEAN OutKill);
BOOLEAN EvaluateRegistryRule(HANDLE ProcessId, PCUNICODE_STRING KeyName, ULONG Operation, PULONG OutCode, PBOOLEAN OutKill);
BOOLEAN EvaluateMemoryRule(HANDLE SourcePid, HANDLE TargetPid, ULONG Operation, PULONG OutCode, PBOOLEAN OutKill);
BOOLEAN EvaluateProcessHandleRule(HANDLE SourcePid, HANDLE TargetPid, ULONG Operation, PULONG OutCode, PBOOLEAN OutKill);

VOID QueueRuleProcessTermination(HANDLE ProcessId, BOOLEAN Kill);
NTSTATUS SendMessageToUser(ULONG Code, ULONG Pid, PWCHAR Path, USHORT PathSize);

FORCEINLINE PVOID PyasAllocate(SIZE_T Size) {
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, PYAS_POOL_TAG);
}

FORCEINLINE VOID PyasFree(PVOID Ptr) {
    if (Ptr) ExFreePoolWithTag(Ptr, PYAS_POOL_TAG);
}