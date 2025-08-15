#pragma once
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntdddisk.h>

#define PIPE_NAME L"\\??\\pipe\\PYAS_Output_Pipe"
#define MAX_MBR_TARGETS 52

#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE 0x0040
#endif
#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS 0x0080
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA 0x0100
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION 0x0200
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif
#ifndef PROCESS_SET_LIMITED_INFORMATION
#define PROCESS_SET_LIMITED_INFORMATION 0x2000
#endif
#ifndef THREAD_IMPERSONATE
#define THREAD_IMPERSONATE 0x0100
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION 0x0200
#endif
#ifndef UINT
typedef unsigned int UINT;
#endif

extern volatile LONG g_LogWorkCount;
extern BOOLEAN g_Unloading;
extern KEVENT g_LogDrainEvent;
extern PDEVICE_OBJECT g_MbrFilterTargets[MAX_MBR_TARGETS];
extern ULONG g_MbrFilterCount;
extern KSPIN_LOCK g_ProtectLock;
extern LARGE_INTEGER g_CmRegHandle;
extern POBJECT_TYPE* IoDriverObjectType;
extern FAST_MUTEX HookMutex;
extern PDRIVER_OBJECT DiskDrvObj;
extern PCSTR PsGetProcessImageFileName(PEPROCESS Process);

VOID DriverUnload(PDRIVER_OBJECT DriverObject);
VOID SendPipeLog(PCSTR msg, SIZE_T len);
VOID UninitImageProtect(VOID);
VOID UninitInjectProtect(VOID);

NTSTATUS ObReferenceObjectByName(
    IN PUNICODE_STRING ObjectName,
    IN ULONG Attributes,
    IN PACCESS_STATE PassedAccessState OPTIONAL,
    IN ACCESS_MASK DesiredAccess OPTIONAL,
    IN POBJECT_TYPE ObjectType,
    IN KPROCESSOR_MODE AccessMode,
    IN OUT PVOID ParseContext OPTIONAL,
    OUT PVOID* Object
);

NTSTATUS FileProtectDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS RegistryProtectCallback(PVOID ctx, PVOID arg1, PVOID arg2);
NTSTATUS InitImageProtect(VOID);
NTSTATUS InitInjectProtect(VOID);

BOOLEAN GetProcessImagePathByPid(HANDLE pid, PUNICODE_STRING ProcessImagePath);
