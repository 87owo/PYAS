#pragma once
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntdddisk.h>
#include <ntddscsi.h>

#define PIPE_NAME L"\\??\\pipe\\PYAS_Output_Pipe"
#define MAX_MBR_TARGETS 256

#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED 0x00000001
#endif
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
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
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
#ifndef FILE_DISPOSITION_DELETE
#define FILE_DISPOSITION_DELETE 0x00000001
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
extern POBJECT_TYPE* IoFileObjectType;
extern FAST_MUTEX HookMutex;
extern PDRIVER_OBJECT DiskDrvObj;
extern PCSTR PsGetProcessImageFileName(PEPROCESS Process);
extern EX_RUNDOWN_REF g_Rundown;
extern PDEVICE_OBJECT g_GuardDevice;

typedef PVOID(NTAPI* _pyas_ExAllocatePool2)(ULONG, SIZE_T, ULONG);
typedef VOID(NTAPI* _pyas_ExFreePool2)(PVOID, ULONG, PVOID, ULONG);
typedef PVOID(NTAPI* _pyas_ExAllocatePoolWithTag)(POOL_TYPE, SIZE_T, ULONG);
typedef VOID(NTAPI* _pyas_ExFreePoolWithTag)(PVOID, ULONG);

static __forceinline PVOID PYAS_ExAllocatePool2(ULONG f, SIZE_T s, ULONG t) {
    static _pyas_ExAllocatePool2 p2 = 0;
    if (!p2) {
        UNICODE_STRING n = RTL_CONSTANT_STRING(L"ExAllocatePool2");
        p2 = (_pyas_ExAllocatePool2)MmGetSystemRoutineAddress(&n);
    }
    if (p2)
        return p2(f, s, t);
    static _pyas_ExAllocatePoolWithTag p1 = 0;
    if (!p1) {
        UNICODE_STRING n = RTL_CONSTANT_STRING(L"ExAllocatePoolWithTag");
        p1 = (_pyas_ExAllocatePoolWithTag)MmGetSystemRoutineAddress(&n);
    }
    if (p1)
        return p1((f & POOL_FLAG_NON_PAGED) ? NonPagedPoolNx : PagedPool, s, t);
    return NULL;
}

static __forceinline VOID PYAS_ExFreePool2(PVOID a, ULONG t, PVOID h, ULONG f) {
    UNREFERENCED_PARAMETER(h);
    UNREFERENCED_PARAMETER(f);
    
    static _pyas_ExFreePool2 p2 = 0;
    if (!p2) {
        UNICODE_STRING n = RTL_CONSTANT_STRING(L"ExFreePool2");
        p2 = (_pyas_ExFreePool2)MmGetSystemRoutineAddress(&n);
    }
    if (p2) {
        p2(a, t, h, f);
        return;
    }
    static _pyas_ExFreePoolWithTag p1 = 0;
    if (!p1) {
        UNICODE_STRING n = RTL_CONSTANT_STRING(L"ExFreePoolWithTag");
        p1 = (_pyas_ExFreePoolWithTag)MmGetSystemRoutineAddress(&n);
    }
    if (p1) {
        p1(a, t);
        return;
    }
}

#define ExAllocatePool2 PYAS_ExAllocatePool2
#define ExFreePool2 PYAS_ExFreePool2

VOID DriverUnload(PDRIVER_OBJECT DriverObject);
VOID SendPipeLog(PCSTR msg, SIZE_T len);
VOID UninitImageProtect(VOID);
VOID UninitInjectProtect(VOID);
VOID UninitRemoteProtect(VOID);
VOID UninitScreenProtect(VOID);

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_opt_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);

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
NTSTATUS InitRemoteProtect(VOID);
NTSTATUS InitScreenProtect(VOID);

BOOLEAN GetProcessImagePathByPid(HANDLE pid, PUNICODE_STRING ProcessImagePath);
