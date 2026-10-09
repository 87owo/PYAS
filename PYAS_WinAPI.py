import struct
from PYAS_Diagnostics import log_exception
import ctypes
import ctypes.wintypes

PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PYAS_PROCESS_TERMINATE_ACCESS = (
    PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION
)


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.wintypes.DWORD),
        ("cntUsage", ctypes.wintypes.DWORD),
        ("th32ProcessID", ctypes.wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.wintypes.LPVOID),
        ("th32ModuleID", ctypes.wintypes.DWORD),
        ("cntThreads", ctypes.wintypes.DWORD),
        ("th32ParentProcessID", ctypes.wintypes.DWORD),
        ("pcPriClassBase", ctypes.wintypes.LONG),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("szExeFile", ctypes.wintypes.WCHAR * 260),
    ]


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.wintypes.DWORD),
        ("dwLocalAddr", ctypes.wintypes.DWORD),
        ("dwLocalPort", ctypes.wintypes.DWORD),
        ("dwRemoteAddr", ctypes.wintypes.DWORD),
        ("dwRemotePort", ctypes.wintypes.DWORD),
        ("dwOwningPid", ctypes.wintypes.DWORD),
    ]


class FILE_NOTIFY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset", ctypes.wintypes.DWORD),
        ("Action", ctypes.wintypes.DWORD),
        ("FileNameLength", ctypes.wintypes.DWORD),
        ("FileName", ctypes.wintypes.WCHAR * 1024),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.wintypes.LPVOID),
        ("PebBaseAddress", ctypes.wintypes.LPVOID),
        ("Reserved2", ctypes.wintypes.LPVOID * 2),
        ("UniqueProcessId", ctypes.wintypes.LPVOID),
        ("Reserved3", ctypes.wintypes.LPVOID),
    ]


class SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.wintypes.DWORD),
        ("i64Size", ctypes.c_int64),
        ("i64NumItems", ctypes.c_int64),
    ]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.wintypes.USHORT),
        ("MaximumLength", ctypes.wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    ]


class FILTER_MESSAGE_HEADER(ctypes.Structure):
    _fields_ = [("ReplyLength", ctypes.wintypes.ULONG), ("MessageId", ctypes.c_uint64)]


class PYAS_MESSAGE(ctypes.Structure):
    _fields_ = [
        ("MessageCode", ctypes.wintypes.ULONG),
        ("ProcessId", ctypes.wintypes.ULONG),
        ("Path", ctypes.wintypes.WCHAR * 1024),
    ]


class PYAS_FULL_MESSAGE(ctypes.Structure):
    _fields_ = [("Header", FILTER_MESSAGE_HEADER), ("Data", PYAS_MESSAGE)]


class PYAS_USER_MESSAGE(ctypes.Structure):
    _fields_ = [("Command", ctypes.wintypes.ULONG), ("Path", ctypes.wintypes.WCHAR * 1024)]


class COPYDATASTRUCT(ctypes.Structure):
    _fields_ = [
        ("dwData", ctypes.c_size_t),
        ("cbData", ctypes.wintypes.DWORD),
        ("lpData", ctypes.c_void_p),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.wintypes.DWORD),
        ("Protect", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.wintypes.DWORD), ("HighPart", ctypes.wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", ctypes.wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", ctypes.wintypes.DWORD),
        ("dwCurrentState", ctypes.wintypes.DWORD),
        ("dwControlsAccepted", ctypes.wintypes.DWORD),
        ("dwWin32ExitCode", ctypes.wintypes.DWORD),
        ("dwServiceSpecificExitCode", ctypes.wintypes.DWORD),
        ("dwCheckPoint", ctypes.wintypes.DWORD),
        ("dwWaitHint", ctypes.wintypes.DWORD),
        ("dwProcessId", ctypes.wintypes.DWORD),
        ("dwServiceFlags", ctypes.wintypes.DWORD),
    ]


class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


class RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


FLT_PORT_FLAG_SYNC_HANDLE = 0x00000001
HRESULT_IO_PENDING = 0x800703E5
ERROR_OPERATION_ABORTED = 995
ERROR_NOT_FOUND = 1168
ERROR_SHARING_VIOLATION = 32
ERROR_LOCK_VIOLATION = 33
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
IOCTL_STORAGE_GET_HOTPLUG_INFO = 0x002D0C14
STORAGE_DEVICE_PROPERTY = 0
PROPERTY_STANDARD_QUERY = 0
INTERNAL_STORAGE_BUS_TYPES = frozenset({1, 3, 8, 10, 11, 17, 18, 19})
FILE_SCAN_DEBOUNCE_SECONDS = 0.35
FILE_SCAN_RETRY_SECONDS = 0.25
FILE_LOCK_RETRY_SECONDS = 0.5
PYAS_CONNECTION_MAGIC = 0x53415950
PYAS_CONNECTION_VERSION = 1
PROCESS_VM_READ = 0x0010
PROCESS_SUSPEND_RESUME = 0x0800
PYAS_PROCESS_SCAN_ACCESS = (
    PROCESS_TERMINATE
    | PROCESS_VM_READ
    | PROCESS_QUERY_INFORMATION
    | PROCESS_SUSPEND_RESUME
    | PROCESS_QUERY_LIMITED_INFORMATION
)
PYAS_PROCESS_NETWORK_ACCESS = (
    PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION
)


class PYAS_CONNECTION_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.wintypes.ULONG),
        ("Version", ctypes.wintypes.ULONG),
        ("Magic", ctypes.wintypes.ULONG),
        ("ProcessId", ctypes.wintypes.ULONG),
    ]


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", ctypes.wintypes.DWORD),
        ("OffsetHigh", ctypes.wintypes.DWORD),
        ("hEvent", ctypes.wintypes.HANDLE),
    ]


class STORAGE_PROPERTY_QUERY(ctypes.Structure):
    _fields_ = [
        ("PropertyId", ctypes.c_int),
        ("QueryType", ctypes.c_int),
        ("AdditionalParameters", ctypes.c_ubyte * 1),
    ]


class STORAGE_DESCRIPTOR_HEADER(ctypes.Structure):
    _fields_ = [("Version", ctypes.wintypes.DWORD), ("Size", ctypes.wintypes.DWORD)]


class STORAGE_DEVICE_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("Version", ctypes.wintypes.DWORD),
        ("Size", ctypes.wintypes.DWORD),
        ("DeviceType", ctypes.c_ubyte),
        ("DeviceTypeModifier", ctypes.c_ubyte),
        ("RemovableMedia", ctypes.c_ubyte),
        ("CommandQueueing", ctypes.c_ubyte),
        ("VendorIdOffset", ctypes.wintypes.DWORD),
        ("ProductIdOffset", ctypes.wintypes.DWORD),
        ("ProductRevisionOffset", ctypes.wintypes.DWORD),
        ("SerialNumberOffset", ctypes.wintypes.DWORD),
        ("BusType", ctypes.c_int),
        ("RawPropertiesLength", ctypes.wintypes.DWORD),
    ]


class STORAGE_HOTPLUG_INFO(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.wintypes.DWORD),
        ("MediaRemovable", ctypes.c_ubyte),
        ("MediaHotplug", ctypes.c_ubyte),
        ("DeviceHotplug", ctypes.c_ubyte),
        ("WriteCacheEnableOverride", ctypes.c_ubyte),
    ]


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.wintypes.DWORD),
        ("Data2", ctypes.wintypes.WORD),
        ("Data3", ctypes.wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pcwszFilePath", ctypes.wintypes.LPCWSTR),
        ("hFile", ctypes.wintypes.HANDLE),
        ("pgKnownSubject", ctypes.wintypes.LPVOID),
    ]


class WINTRUST_DATA_UNION(ctypes.Union):
    _fields_ = [
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("pCatalog", ctypes.wintypes.LPVOID),
        ("pBlob", ctypes.wintypes.LPVOID),
        ("pSgnr", ctypes.wintypes.LPVOID),
        ("pCert", ctypes.wintypes.LPVOID),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.wintypes.LPVOID),
        ("pSIPClientData", ctypes.wintypes.LPVOID),
        ("dwUIChoice", ctypes.wintypes.DWORD),
        ("fdwRevocationChecks", ctypes.wintypes.DWORD),
        ("dwUnionChoice", ctypes.wintypes.DWORD),
        ("u", WINTRUST_DATA_UNION),
        ("dwStateAction", ctypes.wintypes.DWORD),
        ("hWVTStateData", ctypes.wintypes.HANDLE),
        ("pwszURLReference", ctypes.wintypes.LPCWSTR),
        ("dwProvFlags", ctypes.wintypes.DWORD),
        ("dwUIContext", ctypes.wintypes.DWORD),
        ("pSignatureSettings", ctypes.wintypes.LPVOID),
    ]


class WindowsMixin:
    def init_windll(self):
        for name in [
            "ntdll",
            "Psapi",
            "user32",
            "kernel32",
            "iphlpapi",
            "shell32",
            "fltlib",
            "advapi32",
        ]:
            try:
                setattr(self, name.lower(), ctypes.WinDLL(name, use_last_error=True))
            except Exception as e:
                log_exception("PYAS_WinAPI.WindowsMixin.init_windll:323")
                self.write_log("WARN", "init_windll", detail=str(e), success=False)

        self.user32.FindWindowW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
        self.user32.FindWindowW.restype = ctypes.wintypes.HWND
        self.user32.ShowWindow.argtypes = [ctypes.wintypes.HWND, ctypes.c_int]
        self.user32.ShowWindow.restype = ctypes.wintypes.BOOL
        self.user32.SendMessageTimeoutW.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.wintypes.UINT,
            ctypes.wintypes.WPARAM,
            ctypes.c_void_p,
            ctypes.wintypes.UINT,
            ctypes.wintypes.UINT,
            ctypes.c_void_p,
        ]
        self.user32.SendMessageTimeoutW.restype = ctypes.wintypes.LPARAM

        self.user32.WindowFromPoint.argtypes = [POINT]
        self.user32.WindowFromPoint.restype = ctypes.wintypes.HWND
        self.user32.GetAncestor.argtypes = [ctypes.wintypes.HWND, ctypes.c_uint]
        self.user32.GetAncestor.restype = ctypes.wintypes.HWND
        self.user32.GetCursorPos.argtypes = [ctypes.POINTER(POINT)]
        self.user32.GetCursorPos.restype = ctypes.wintypes.BOOL
        self.user32.GetWindowRect.argtypes = [ctypes.wintypes.HWND, ctypes.POINTER(RECT)]
        self.user32.GetWindowRect.restype = ctypes.wintypes.BOOL
        self.user32.SetWindowPos.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.wintypes.HWND,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.wintypes.UINT,
        ]
        self.user32.SetWindowPos.restype = ctypes.wintypes.BOOL
        self.user32.SetLayeredWindowAttributes.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.wintypes.DWORD,
            ctypes.c_byte,
            ctypes.wintypes.DWORD,
        ]
        self.user32.SetLayeredWindowAttributes.restype = ctypes.wintypes.BOOL
        self.user32.CreateWindowExW.restype = ctypes.wintypes.HWND

        self.ntdll.NtQueryInformationProcess.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.ULONG,
            ctypes.c_void_p,
            ctypes.wintypes.ULONG,
            ctypes.POINTER(ctypes.wintypes.ULONG),
        ]
        self.ntdll.NtQueryInformationProcess.restype = ctypes.wintypes.ULONG
        self.ntdll.NtSuspendProcess.argtypes = [ctypes.wintypes.HANDLE]
        self.ntdll.NtSuspendProcess.restype = ctypes.c_ulong
        self.ntdll.NtResumeProcess.argtypes = [ctypes.wintypes.HANDLE]
        self.ntdll.NtResumeProcess.restype = ctypes.c_ulong

        self.shell32.CommandLineToArgvW.argtypes = [
            ctypes.wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_int),
        ]
        self.shell32.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.wintypes.LPWSTR)
        self.shell32.SHEmptyRecycleBinW.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.c_wchar_p,
            ctypes.wintypes.DWORD,
        ]
        self.shell32.SHEmptyRecycleBinW.restype = ctypes.c_long
        self.shell32.SHQueryRecycleBinW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(SHQUERYRBINFO)]
        self.shell32.SHQueryRecycleBinW.restype = ctypes.c_long

        self.fltlib.FilterConnectCommunicationPort.argtypes = [
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.wintypes.HANDLE),
        ]
        self.fltlib.FilterConnectCommunicationPort.restype = ctypes.c_long
        self.fltlib.FilterGetMessage.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.wintypes.DWORD,
            ctypes.c_void_p,
        ]
        self.fltlib.FilterGetMessage.restype = ctypes.c_long
        self.fltlib.FilterSendMessage.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.wintypes.DWORD,
            ctypes.POINTER(ctypes.wintypes.DWORD),
        ]
        self.fltlib.FilterSendMessage.restype = ctypes.c_long
        self.fltlib.FilterUnload.argtypes = [ctypes.wintypes.LPCWSTR]
        self.fltlib.FilterUnload.restype = ctypes.c_long

        self.advapi32.OpenProcessToken.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.DWORD,
            ctypes.POINTER(ctypes.wintypes.HANDLE),
        ]
        self.advapi32.OpenProcessToken.restype = ctypes.wintypes.BOOL
        self.advapi32.LookupPrivilegeValueW.argtypes = [
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR,
            ctypes.POINTER(LUID),
        ]
        self.advapi32.LookupPrivilegeValueW.restype = ctypes.wintypes.BOOL
        self.advapi32.AdjustTokenPrivileges.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.BOOL,
            ctypes.POINTER(TOKEN_PRIVILEGES),
            ctypes.wintypes.DWORD,
            ctypes.POINTER(TOKEN_PRIVILEGES),
            ctypes.POINTER(ctypes.wintypes.DWORD),
        ]
        self.advapi32.AdjustTokenPrivileges.restype = ctypes.wintypes.BOOL
        self.advapi32.OpenSCManagerW.argtypes = [
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.DWORD,
        ]
        self.advapi32.OpenSCManagerW.restype = ctypes.wintypes.HANDLE
        self.advapi32.CreateServiceW.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.wintypes.DWORD),
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR,
        ]
        self.advapi32.CreateServiceW.restype = ctypes.wintypes.HANDLE
        self.advapi32.OpenServiceW.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.DWORD,
        ]
        self.advapi32.OpenServiceW.restype = ctypes.wintypes.HANDLE
        self.advapi32.ChangeServiceConfigW.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.wintypes.DWORD),
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR,
        ]
        self.advapi32.ChangeServiceConfigW.restype = ctypes.wintypes.BOOL
        self.advapi32.StartServiceW.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.DWORD,
            ctypes.POINTER(ctypes.wintypes.LPCWSTR),
        ]
        self.advapi32.StartServiceW.restype = ctypes.wintypes.BOOL
        self.advapi32.QueryServiceStatusEx.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.wintypes.DWORD,
            ctypes.POINTER(ctypes.wintypes.DWORD),
        ]
        self.advapi32.QueryServiceStatusEx.restype = ctypes.wintypes.BOOL
        self.advapi32.DeleteService.argtypes = [ctypes.wintypes.HANDLE]
        self.advapi32.DeleteService.restype = ctypes.wintypes.BOOL
        self.advapi32.CloseServiceHandle.argtypes = [ctypes.wintypes.HANDLE]
        self.advapi32.CloseServiceHandle.restype = ctypes.wintypes.BOOL

        self.kernel32.GetCurrentProcess.argtypes = []
        self.kernel32.GetCurrentProcess.restype = ctypes.wintypes.HANDLE
        self.kernel32.CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE
        self.kernel32.CreateToolhelp32Snapshot.argtypes = [
            ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD,
        ]
        self.kernel32.Process32FirstW.restype = ctypes.wintypes.BOOL
        self.kernel32.Process32FirstW.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p]
        self.kernel32.Process32NextW.restype = ctypes.wintypes.BOOL
        self.kernel32.Process32NextW.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p]
        self.kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE
        self.kernel32.OpenProcess.argtypes = [
            ctypes.wintypes.DWORD,
            ctypes.wintypes.BOOL,
            ctypes.wintypes.DWORD,
        ]
        self.kernel32.CloseHandle.restype = ctypes.wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
        self.kernel32.CreateEventW.argtypes = [
            ctypes.c_void_p,
            ctypes.wintypes.BOOL,
            ctypes.wintypes.BOOL,
            ctypes.wintypes.LPCWSTR,
        ]
        self.kernel32.CreateEventW.restype = ctypes.wintypes.HANDLE
        self.kernel32.WaitForSingleObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD]
        self.kernel32.WaitForSingleObject.restype = ctypes.wintypes.DWORD
        self.kernel32.CancelIoEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p]
        self.kernel32.CancelIoEx.restype = ctypes.wintypes.BOOL
        self.kernel32.GetOverlappedResult.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.wintypes.DWORD),
            ctypes.wintypes.BOOL,
        ]
        self.kernel32.GetOverlappedResult.restype = ctypes.wintypes.BOOL
        self.kernel32.TerminateProcess.restype = ctypes.wintypes.BOOL
        self.kernel32.TerminateProcess.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_uint]
        self.kernel32.CreateMutexW.restype = ctypes.wintypes.HANDLE
        self.kernel32.CreateMutexW.argtypes = [
            ctypes.c_void_p,
            ctypes.wintypes.BOOL,
            ctypes.c_wchar_p,
        ]
        self.kernel32.CreateFileW.restype = ctypes.wintypes.HANDLE
        self.kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.HANDLE,
        ]
        self.kernel32.DeviceIoControl.restype = ctypes.wintypes.BOOL
        self.kernel32.DeviceIoControl.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.wintypes.DWORD,
            ctypes.POINTER(ctypes.wintypes.DWORD),
            ctypes.c_void_p,
        ]
        self.kernel32.ReadProcessMemory.restype = ctypes.wintypes.BOOL
        self.kernel32.ReadProcessMemory.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.kernel32.QueryFullProcessImageNameW.restype = ctypes.wintypes.BOOL
        self.kernel32.QueryFullProcessImageNameW.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.LPWSTR,
            ctypes.POINTER(ctypes.wintypes.DWORD),
        ]
        self.kernel32.QueryDosDeviceW.restype = ctypes.wintypes.DWORD
        self.kernel32.QueryDosDeviceW.argtypes = [
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPWSTR,
            ctypes.wintypes.DWORD,
        ]
        self.kernel32.GetProcessIoCounters.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.POINTER(IO_COUNTERS),
        ]
        self.kernel32.GetProcessIoCounters.restype = ctypes.wintypes.BOOL
        self.kernel32.VirtualQueryEx.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(MEMORY_BASIC_INFORMATION),
            ctypes.c_size_t,
        ]
        self.kernel32.VirtualQueryEx.restype = ctypes.c_size_t
        self.kernel32.SetProcessWorkingSetSize.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_size_t,
            ctypes.c_size_t,
        ]
        self.kernel32.SetProcessWorkingSetSize.restype = ctypes.wintypes.BOOL

        self.psapi.GetMappedFileNameW.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.wintypes.LPWSTR,
            ctypes.wintypes.DWORD,
        ]
        self.psapi.GetMappedFileNameW.restype = ctypes.wintypes.DWORD


def iter_file_notifications(buffer, size):
    view = memoryview(buffer).cast("B")

    if size < 0 or size > len(view):
        raise ValueError("Invalid file notification buffer size")

    offset = 0

    while offset < size:
        if offset + 12 > size:
            raise ValueError("Truncated file notification header")

        next_offset, action, length = struct.unpack_from("<III", view, offset)

        if length % 2 or offset + 12 + length > size:
            raise ValueError("Invalid file notification length")

        if next_offset and (
            next_offset < 12 + length or next_offset % 4 or offset + next_offset >= size
        ):
            raise ValueError("Invalid file notification offset")

        filename = bytes(view[offset + 12 : offset + 12 + length]).decode(
            "utf-16-le", errors="surrogatepass"
        )
        yield action, filename

        if not next_offset:
            break

        offset += next_offset
