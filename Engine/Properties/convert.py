import os, sys, time, ctypes, sqlite3, datetime, pefile, math, hashlib
import numpy as np
import ctypes.wintypes

####################################################################################################

DB_PATH = "pe_features.db"
BATCH_SIZE = 1000
MAX_FILE_SIZE = 256 * 1024 * 1024
TARGET_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.ocx', '.scr', '.efi', '.acm', '.ax', '.cpl', '.drv', '.com', '.mui', '.pyd'
}

####################################################################################################

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pcwszFilePath", ctypes.wintypes.LPCWSTR),
        ("hFile", ctypes.wintypes.HANDLE),
        ("pgKnownSubject", ctypes.wintypes.LPVOID)
    ]

class WINTRUST_DATA_UNION(ctypes.Union):
    _fields_ = [
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("pCatalog", ctypes.wintypes.LPVOID),
        ("pBlob", ctypes.wintypes.LPVOID),
        ("pSgnr", ctypes.wintypes.LPVOID),
        ("pCert", ctypes.wintypes.LPVOID)
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
        ("pSignatureSettings", ctypes.wintypes.LPVOID)
    ]

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.wintypes.DWORD),
        ("Data2", ctypes.wintypes.WORD),
        ("Data3", ctypes.wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8)
    ]

V2_GUID = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

####################################################################################################

def verify_signature(file_path):
    if os.name != 'nt':
        return 0
    try:
        wintrust = ctypes.windll.wintrust
        wintrust.WinVerifyTrust.argtypes = [ctypes.wintypes.HWND, ctypes.POINTER(GUID), ctypes.wintypes.LPVOID]
        wintrust.WinVerifyTrust.restype = ctypes.wintypes.LONG

        abs_path = os.path.abspath(file_path)

        fi = WINTRUST_FILE_INFO()
        fi.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        fi.pcwszFilePath = abs_path
        fi.hFile = None
        fi.pgKnownSubject = None

        wt_union = WINTRUST_DATA_UNION()
        wt_union.pFile = ctypes.pointer(fi)

        td = WINTRUST_DATA()
        td.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        td.pPolicyCallbackData = None
        td.pSIPClientData = None
        td.dwUIChoice = 2
        td.fdwRevocationChecks = 0
        td.dwUnionChoice = 1
        td.u = wt_union
        td.dwStateAction = 0
        td.hWVTStateData = None
        td.pwszURLReference = None
        td.dwProvFlags = 0
        td.dwUIContext = 0
        td.pSignatureSettings = None

        return 1 if wintrust.WinVerifyTrust(None, ctypes.byref(V2_GUID), ctypes.byref(td)) == 0 else 0
    except Exception as e:
        print(e)
        return 0

####################################################################################################

class Features:
    API_CAT_MAPPING = {
        'ProcessControl': {
            'CreateProcessA', 'CreateProcessW', 'WinExec', 'ShellExecuteA', 'ShellExecuteW',
            'ShellExecuteExW', 'ExitProcess', 'TerminateProcess', 'OpenProcess', 'GetExitCodeProcess',
            'SetThreadPriority', 'GetThreadPriority', 'GetCurrentProcess', 'GetCurrentProcessId',
            'GetModuleFileNameA', 'GetCommandLineA', 'GetModuleFileNameW', 'GetStartupInfoW'
        },
        'Injection': {
            'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx', 'WriteProcessMemory', 
            'ReadProcessMemory', 'CreateRemoteThread', 'QueueUserAPC', 'SetThreadContext', 'GetThreadContext', 
            'Wow64SetThreadContext', 'NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'RtlCreateUserThread', 
            'SetWindowsHookExA', 'SetWindowsHookExW', 'UnhookWindowsHookEx', 'LoadLibraryA', 'LoadLibraryW', 
            'LoadLibraryExA', 'LoadLibraryExW', 'GetProcAddress', 'GetModuleHandleA', 'GetModuleHandleW',
            'FreeLibrary', 'CreateFileMappingA', 'CreateFileMappingW', 'MapViewOfFile', 'UnmapViewOfSection',
            'VirtualFree', 'VirtualQuery'
        },
        'Synchronization': {
            'WaitForSingleObject', 'WaitForSingleObjectEx', 'WaitForMultipleObjects', 'WaitForMultipleObjectsEx',
            'CreateMutexA', 'CreateMutexW', 'OpenMutexW', 'ReleaseMutex', 'CreateEventA', 'CreateEventW', 
            'OpenEventW', 'SetEvent', 'ResetEvent', 'EnterCriticalSection', 'LeaveCriticalSection', 
            'InitializeCriticalSection', 'DeleteCriticalSection', 'Sleep', 'SleepEx',
            'InitializeCriticalSectionAndSpinCount', 'InterlockedDecrement', 'InterlockedIncrement', 
            'InterlockedExchange', 'InterlockedCompareExchange', 'SetTimer', 'KillTimer'
        },
        'MultiThreading': {
            'CreateThread', 'ResumeThread', 'SuspendThread', 'ExitThread', 'TerminateThread',
            'GetCurrentThread', 'GetCurrentThreadId', 'TlsAlloc', 'TlsSetValue', 'TlsGetValue',
            'CreateThreadpoolWork', 'SubmitThreadpoolWork', 'TlsFree'
        },
        'Network': {
            'socket', 'connect', 'send', 'recv', 'bind', 'listen', 'accept', 'gethostbyname', 'getaddrinfo',
            'WSAStartup', 'WSACleanup', 'WSAIoctl', 'WSASocketA', 'WSASocketW', 'closesocket', 'htons',
            'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW', 'InternetOpenUrlA', 
            'InternetOpenUrlW', 'HttpOpenRequestA', 'HttpOpenRequestW', 'HttpSendRequestA', 'HttpSendRequestW',
            'InternetReadFile', 'URLDownloadToFileA', 'URLDownloadToFileW', 'DnsQuery_A', 'DnsQuery_W'
        },
        'Encryption': {
            'CryptAcquireContextA', 'CryptAcquireContextW', 'CryptCreateHash', 'CryptHashData', 
            'CryptDeriveKey', 'CryptEncrypt', 'CryptDecrypt', 'CryptDestroyKey', 'CryptDestroyHash',
            'CryptReleaseContext', 'CryptGenKey', 'CryptImportKey', 'CryptExportKey'
        },
        'DataObfuscation': {
            'RtlDecompressBuffer', 'MultiByteToWideChar', 'WideCharToMultiByte', 'Base64Decode', 
            'CryptDecodeObject', 'IsDBCSLeadByte', 'CharUpperA', 'CharLowerA',
            'GetStringTypeW', 'LCMapStringW', 'IsValidCodePage', 'DecodePointer', 'EncodePointer'
        },
        'FileIO': {
            'CreateFileA', 'CreateFileW', 'WriteFile', 'ReadFile', 'DeleteFileA', 'DeleteFileW',
            'CopyFileA', 'CopyFileW', 'MoveFileA', 'MoveFileW', 'FindFirstFileA', 'FindNextFileA',
            'GetTempPathA', 'GetTempPathW', 'GetTempFileNameA', 'GetTempFileNameW', 'SetFileAttributesA', 
            'SetFileAttributesW', 'DeviceIoControl', 'SetFileTime', 'GetFileSize', 'GetFileSizeEx',
            'SetFilePointer', 'FlushFileBuffers', 'ConnectNamedPipe', 'PeekNamedPipe',
            'CloseHandle', 'GetFileType', 'SetStdHandle', 'SetFilePointerEx', 'FindClose', 
            'SetHandleCount', 'SetEndOfFile', 'GetFullPathNameA', 'GetFileAttributesA'
        },
        'Registry': {
            'RegOpenKeyExA', 'RegOpenKeyExW', 'RegSetValueExA', 'RegSetValueExW', 
            'RegCreateKeyExA', 'RegCreateKeyExW', 'RegDeleteKeyA', 'RegDeleteKeyW',
            'RegEnumValueA', 'RegEnumValueW', 'RegQueryValueExA', 'RegQueryValueExW',
            'RegDeleteValueA', 'RegDeleteValueW', 'RegCloseKey'
        },
        'Services': {
            'OpenSCManagerA', 'OpenSCManagerW', 'CreateServiceA', 'CreateServiceW',
            'StartServiceA', 'StartServiceW', 'ControlService', 'DeleteService'
        },
        'Privileges': {
            'AdjustTokenPrivileges', 'LookupPrivilegeValueA', 'LookupPrivilegeValueW', 
            'OpenProcessToken', 'NetUserAdd', 'NetLocalGroupAddMembers', 'IsAdmin', 
            'GetUserNameA', 'GetUserNameW'
        },
        'Native': {
            'RtlUnwind', 'RtlVirtualUnwind', 'RtlCaptureContext', 'RtlLookupFunctionEntry',
            'NtClose', 'NtQueryInformationProcess', 'RtlAllocateHeap', 'RtlFreeHeap',
            'GetSystemTimeAsFileTime', 'GetLocalTime', 'GlobalMemoryStatus', 
            'GetVersionExA', 'GetVersionExW', 'GetComputerNameA', 'GetComputerNameW',
            'GetLastError', 'GetACP', 'RaiseException', 'SetLastError', 'GetEnvironmentStringsW', 
            'FreeEnvironmentStringsW', 'GetLocaleInfoA', 'lstrlenA', 'GetVersion', 'GetSystemInfo', 
            'CompareStringA'
        },
        'DotNet': {
            '_CorExeMain', '_CorDllMain'
        },
        'AntiDebug': {
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugStringA', 'OutputDebugStringW',
            'GetTickCount', 'GetTickCount64', 'QueryPerformanceCounter', 'FindWindowA', 'FindWindowW',
            'EnumWindows', 'EnumChildWindows', 'GetWindowRect', 'GetClientRect', 'SetWindowDisplayAffinity',
            'UnhandledExceptionFilter', 'SetUnhandledExceptionFilter', 'IsProcessorFeaturePresent', 
            'SetErrorMode', 'GetTimeZoneInformation', 'GetDriveTypeW', 'GetDiskFreeSpaceA'
        },
        'Keylogging': {
            'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState', 'MapVirtualKeyA', 'MapVirtualKeyW',
            'ToAscii', 'ToAsciiEx', 'ToUnicode', 'ToUnicodeEx', 'GetKeyNameTextA', 'GetForegroundWindow',
            'KeybdEvent', 'SendInput', 'MapVirtualKeyExA', 'MapVirtualKeyExW', 'CallNextHookEx'
        },
        'Input': {
            'GetCursorPos', 'SetCursorPos', 'MouseEvent', 'GetDoubleClickTime', 
            'GetCapture', 'SetCapture'
        },
        'ScreenCapture': {
            'BitBlt', 'StretchBlt', 'GetDC', 'GetWindowDC', 'CreateCompatibleDC', 'CreateCompatibleBitmap',
            'GdipSaveImageToFile', 'PrintWindow', 'GetDesktopWindow', 'CreateDCW', 'CreateDCA',
            'SelectObject', 'DeleteDC', 'DeleteObject', 'GetDeviceCaps', 'GetSystemMetrics'
        },
        'Graphics': {
            'Direct3DCreate9', 'D3D11CreateDevice'
        },
        'Audio': {
            'WaveInOpen', 'WaveInClose', 'WaveInStart', 'WaveInStop'
        },
        'Clipboard': {
            'OpenClipboard', 'CloseClipboard', 'GetClipboardData', 'SetClipboardData'
        },
        'Camera': {
            'CapCreateCaptureWindowA', 'CapCreateCaptureWindowW'
        },
        'Memory': {
            'HeapAlloc', 'HeapFree', 'HeapSize', 'HeapCreate', 'GetProcessHeap',
            'LocalAlloc', 'LocalFree', 'GlobalAlloc', 'GlobalFree', 'GlobalUnlock',
            'HeapDestroy', 'GlobalLock', 'SysFreeString', 'SysAllocStringLen'
        },
        'Resource': {
            'LoadResource', 'SizeofResource', 'LockResource', 'FreeResource', 'FindResourceA'
        },
        'WindowControl': {
            'ShowWindow', 'DestroyWindow', 'TranslateMessage', 'DispatchMessageA', 'GetWindow',
            'PeekMessageA', 'GetWindowLongA', 'CallWindowProcA', 'SetWindowLongA', 'GetWindowTextA',
            'ScreenToClient', 'GetActiveWindow', 'CreateWindowExA', 'DefWindowProcA', 'GetMessageA',
            'RegisterClassA', 'UnregisterClassA', 'MessageBoxA'
        },
        'COM': {
            'CoCreateInstance', 'CoUninitialize', 'CoInitialize'
        }
    }

    TARGET_DLLS = {
        'kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 'shell32.dll', 'ntdll.dll', 'hal.dll',
        'ws2_32.dll', 'wsock32.dll', 'wininet.dll', 'winhttp.dll', 'urlmon.dll', 'crypt32.dll', 'bcrypt.dll',
        'psapi.dll', 'dbghelp.dll', 'imagehlp.dll', 'shlwapi.dll', 'ole32.dll', 'oleaut32.dll', 'comctl32.dll',
        'mscoree.dll', 'vbscript.dll', 'netapi32.dll', 'iphlpapi.dll', 'wtsapi32.dll', 'version.dll', 'winmm.dll'
    }

    BASE_SCHEMA = [
        "FileEntropy", "SectionMeanEntropy", "IsExe", "IsDll", "IsDriver", "Is64Bit", "Machine", "Magic",
        "TimeDateStamp", "CheckSum", "ImageBase", "SizeOfImage", "SizeOfHeaders",
        "Characteristics", "DllCharacteristics", "Subsystem", "LoaderFlags",
        "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode", 
        "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint",
        "BaseOfCode", "SectionAlignment", "FileAlignment",
        "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
        "MajorImageVersion", "MinorImageVersion",
        "MajorSubsystemVersion", "MinorSubsystemVersion",
        "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit",
        "NumberOfSections", "NumberOfRvaAndSizes", "PointerToSymbolTable", "NumberOfSymbols",
        "SizeOfOptionalHeader",
        
        "TextSectionMaxEntropy", "TextSectionMeanEntropy", "TextSizeRatio", 
        "DataSectionMaxEntropy", "DataSectionMeanEntropy", "DataSizeRatio", 
        "RsrcSectionMaxEntropy", "RsrcSectionMeanEntropy", "RsrcSizeRatio", 
        "SectionCount", "ExecutableSections", 
        "WritableSections", "ReadableSections", "SectionException",

        "Char_00000020_Count", "Char_00000020_MeanEntropy",
        "Char_00000040_Count", "Char_00000040_MeanEntropy",
        "Char_00000080_Count", "Char_00000080_MeanEntropy",
        "Char_02000000_Count", "Char_02000000_MeanEntropy",
        "Char_20000000_Count", "Char_20000000_MeanEntropy",
        "Char_40000000_Count", "Char_40000000_MeanEntropy",
        "Char_80000000_Count", "Char_80000000_MeanEntropy",
        
        "IconCount", "ApiCount", "ExportCount", "DebugCount", "ExceptionCount",
        "ImportCount", "ImportFunctionCount",
        
        "FileDescriptionLength", "FileVersionLength", "ProductNameLength", 
        "ProductVersionLength", "CompanyNameLength", "LegalCopyrightLength", 
        "CommentsLength", "InternalNameLength", "LegalTrademarksLength",
        "SpecialBuildLength", "PrivateBuildLength",
        
        "TrustSigned", "IsDebug", "IsPatched", "IsPrivateBuild", "IsPreRelease", 
        "IsSpecialBuild", "IsAdmin", "IsInstall", "HasTlsCallbacks", 
        "HasInvalidTimestamp", "HasRelocationDirectory", "HasPacked", "FileTimeException"
    ]

    CAT_SCHEMA = [f"Cat_{k}" for k in sorted(API_CAT_MAPPING.keys())]
    DLL_SCHEMA = [f"Dll_{d.replace('.', '_')}" for d in sorted(TARGET_DLLS)]
    
    _ALL_APIS = {api for apis in API_CAT_MAPPING.values() for api in apis}
    API_SCHEMA = [f"Api_{api}" for api in sorted(_ALL_APIS)]
    
    SCHEMA = BASE_SCHEMA + CAT_SCHEMA + DLL_SCHEMA + API_SCHEMA
    
    _API_TO_CATS = {}
    for _cat, _apis in API_CAT_MAPPING.items():
        for _api in _apis:
            if _api not in _API_TO_CATS:
                _API_TO_CATS[_api] = []
            _API_TO_CATS[_api].append(_cat)

    PACKERS = {
        'upx', 'aspack', 'asprotect', 'pecompact', 'upack', 'fsg', 'mew', 
        'mpress', 'ezip', 'pklt', 'shrink', 'petite', 'telock',
        'themida', 'winlicense', 'tmd', 'vmp', 'enigma', 'obsidium', 
        'pelock', 'exestealth', 'yoda', 'armadillo', 'zprotect',
        'sforce', 'starforce', 'qihoo', 'wisevec', 'megastop',
    }
    INSTALLER_SIGS = [b"Nullsoft.NSIS", b"Inno Setup", b"7-Zip.7zip", b"InstallShield"]

####################################################################################################

def safe_float(val):
    try:
        f = float(val)
        if math.isinf(f) or math.isnan(f): return 0.0
        return f
    except:
        return 0.0

####################################################################################################

def calc_entropy(data):
    if not data: return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256)
    probs = counts[counts > 0] / len(arr)
    return float(-np.sum(probs * np.log2(probs)))

def safe_div(n, d): 
    return float(n) / d if d > 0 else 0.0

def process_single_file_content(file_bytes, file_path):
    fsize = len(file_bytes)
    if fsize == 0: return None

    fts = {k: 0.0 for k in Features.SCHEMA}
    pe = None
    try:
        pe = pefile.PE(data=file_bytes, fast_load=True)
        fts['TrustSigned'] = verify_signature(file_path)

        fh = pe.FILE_HEADER
        fts['Machine'] = fh.Machine
        fts['NumberOfSections'] = fh.NumberOfSections
        fts['TimeDateStamp'] = fh.TimeDateStamp
        fts['PointerToSymbolTable'] = fh.PointerToSymbolTable
        fts['NumberOfSymbols'] = fh.NumberOfSymbols
        fts['SizeOfOptionalHeader'] = fh.SizeOfOptionalHeader
        fts['Characteristics'] = fh.Characteristics

        curr_ts = datetime.datetime.utcnow().timestamp()
        fts['HasInvalidTimestamp'] = 1.0 if (fh.TimeDateStamp < 631152000 or fh.TimeDateStamp > curr_ts + 2592000) else 0.0
        fts['FileTimeException'] = 1.0 if fh.TimeDateStamp == 0 else 0.0

        if hasattr(pe, 'OPTIONAL_HEADER'):
            op = pe.OPTIONAL_HEADER
            fts['Magic'] = getattr(op, 'Magic', 0)
            fts['MajorLinkerVersion'] = getattr(op, 'MajorLinkerVersion', 0)
            fts['MinorLinkerVersion'] = getattr(op, 'MinorLinkerVersion', 0)
            fts['SizeOfCode'] = getattr(op, 'SizeOfCode', 0)
            fts['SizeOfInitializedData'] = getattr(op, 'SizeOfInitializedData', 0)
            fts['SizeOfUninitializedData'] = getattr(op, 'SizeOfUninitializedData', 0)
            fts['AddressOfEntryPoint'] = getattr(op, 'AddressOfEntryPoint', 0)
            fts['BaseOfCode'] = getattr(op, 'BaseOfCode', 0)
            fts['ImageBase'] = getattr(op, 'ImageBase', 0)
            fts['SectionAlignment'] = getattr(op, 'SectionAlignment', 0)
            fts['FileAlignment'] = getattr(op, 'FileAlignment', 0)
            fts['MajorOperatingSystemVersion'] = getattr(op, 'MajorOperatingSystemVersion', 0)
            fts['MinorOperatingSystemVersion'] = getattr(op, 'MinorOperatingSystemVersion', 0)
            fts['MajorImageVersion'] = getattr(op, 'MajorImageVersion', 0)
            fts['MinorImageVersion'] = getattr(op, 'MinorImageVersion', 0)
            fts['MajorSubsystemVersion'] = getattr(op, 'MajorSubsystemVersion', 0)
            fts['MinorSubsystemVersion'] = getattr(op, 'MinorSubsystemVersion', 0)
            fts['SizeOfImage'] = getattr(op, 'SizeOfImage', 0)
            fts['SizeOfHeaders'] = getattr(op, 'SizeOfHeaders', 0)
            fts['CheckSum'] = getattr(op, 'CheckSum', 0)
            fts['Subsystem'] = getattr(op, 'Subsystem', 0)
            fts['DllCharacteristics'] = getattr(op, 'DllCharacteristics', 0)
            fts['SizeOfStackReserve'] = getattr(op, 'SizeOfStackReserve', 0)
            fts['SizeOfStackCommit'] = getattr(op, 'SizeOfStackCommit', 0)
            fts['SizeOfHeapReserve'] = getattr(op, 'SizeOfHeapReserve', 0)
            fts['SizeOfHeapCommit'] = getattr(op, 'SizeOfHeapCommit', 0)
            fts['LoaderFlags'] = getattr(op, 'LoaderFlags', 0)
            fts['NumberOfRvaAndSizes'] = getattr(op, 'NumberOfRvaAndSizes', 0)
            fts['Is64Bit'] = 1.0 if fh.Machine in (0x8664, 0xAA64, 0x0200) else 0.0
            fts['IsExe'] = 1.0 if pe.is_exe() else 0.0
            fts['IsDll'] = 1.0 if pe.is_dll() else 0.0
            fts['IsDriver'] = 1.0 if fts['Subsystem'] == 1 else 0.0

            if hasattr(op, 'DATA_DIRECTORY'):
                reloc_idx = pefile.DIRECTORY_ENTRY.get('IMAGE_DIRECTORY_ENTRY_BASERELOC', 5)
                if len(op.DATA_DIRECTORY) > reloc_idx and op.DATA_DIRECTORY[reloc_idx].Size > 0:
                    fts['HasRelocationDirectory'] = 1.0

        try:
            fts['FileEntropy'] = calc_entropy(file_bytes)
        except Exception:
            pass

        sec_entropies = []
        text_entropies = []
        data_entropies = []
        rsrc_entropies = []
        char_flags = [0x00000020, 0x00000040, 0x00000080, 0x02000000, 0x20000000, 0x40000000, 0x80000000]

        if hasattr(pe, 'sections'):
            fts['SectionCount'] = len(pe.sections)
            for section in pe.sections:
                try: 
                    name = section.Name.decode('ascii', 'ignore').strip('\x00')
                except Exception: 
                    name = ""
                    
                try: 
                    s_data = section.get_data()
                    s_entropy = calc_entropy(s_data)
                except Exception: 
                    s_data = b""
                    s_entropy = 0.0

                sec_entropies.append(s_entropy)

                if any(p in name.lower() for p in Features.PACKERS): fts['HasPacked'] = 1.0
                if section.Characteristics & 0x20000000: fts['ExecutableSections'] += 1.0
                if section.Characteristics & 0x80000000: fts['WritableSections'] += 1.0
                if section.Characteristics & 0x40000000: fts['ReadableSections'] += 1.0
                if section.SizeOfRawData + section.PointerToRawData > fsize: fts['SectionException'] = 1.0

                for flag in char_flags:
                    if section.Characteristics & flag:
                        fts[f'Char_{flag:08X}_Count'] += 1.0
                        fts[f'Char_{flag:08X}_MeanEntropy'] += s_entropy

                ratio = safe_div(section.SizeOfRawData, fsize)
                if name.startswith('.text'):
                    text_entropies.append(s_entropy)
                    fts['TextSizeRatio'] += ratio
                elif name.startswith('.data'):
                    data_entropies.append(s_entropy)
                    fts['DataSizeRatio'] += ratio
                elif name.startswith('.rsrc'):
                    rsrc_entropies.append(s_entropy)
                    fts['RsrcSizeRatio'] += ratio
                    if b"requireAdministrator" in s_data: fts['IsAdmin'] = 1.0
                    for sig in Features.INSTALLER_SIGS:
                        if sig in s_data:
                            fts['IsInstall'] = 1.0
                            break

        fts['SectionMeanEntropy'] = safe_div(sum(sec_entropies), len(sec_entropies))
        fts['TextSectionMaxEntropy'] = max(text_entropies) if text_entropies else 0.0
        fts['TextSectionMeanEntropy'] = safe_div(sum(text_entropies), len(text_entropies))
        fts['DataSectionMaxEntropy'] = max(data_entropies) if data_entropies else 0.0
        fts['DataSectionMeanEntropy'] = safe_div(sum(data_entropies), len(data_entropies))
        fts['RsrcSectionMaxEntropy'] = max(rsrc_entropies) if rsrc_entropies else 0.0
        fts['RsrcSectionMeanEntropy'] = safe_div(sum(rsrc_entropies), len(rsrc_entropies))

        for flag in char_flags:
            fts[f'Char_{flag:08X}_MeanEntropy'] = safe_div(fts[f'Char_{flag:08X}_MeanEntropy'], fts[f'Char_{flag:08X}_Count'])

        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']
            ])
        except Exception:
            pass

        if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and hasattr(pe.DIRECTORY_ENTRY_TLS, 'struct'):
            if getattr(pe.DIRECTORY_ENTRY_TLS.struct, 'AddressOfCallBacks', 0) != 0:
                fts['HasTlsCallbacks'] = 1.0

        if hasattr(pe, 'VS_FIXEDFILEINFO') and len(pe.VS_FIXEDFILEINFO) > 0:
            flags = getattr(pe.VS_FIXEDFILEINFO[0], 'FileFlags', 0)
            fts['IsDebug'] = 1.0 if flags & 0x1 else 0.0
            fts['IsPreRelease'] = 1.0 if flags & 0x2 else 0.0
            fts['IsPatched'] = 1.0 if flags & 0x4 else 0.0
            fts['IsPrivateBuild'] = 1.0 if flags & 0x8 else 0.0
            fts['IsSpecialBuild'] = 1.0 if flags & 0x20 else 0.0

        if hasattr(pe, 'FileInfo'):
            for fileinfo_list in pe.FileInfo:
                for fileinfo in fileinfo_list:
                    if getattr(fileinfo, 'name', '') in ('StringFileInfo', b'StringFileInfo'):
                        for st in getattr(fileinfo, 'StringTable', []):
                            for key, val in st.entries.items():
                                try:
                                    k = key.decode('utf-8', 'ignore') if isinstance(key, bytes) else str(key)
                                    v = val.decode('utf-8', 'ignore') if isinstance(val, bytes) else str(val)
                                    length = len(v)
                                    if k == 'FileDescription': fts['FileDescriptionLength'] = length
                                    elif k == 'FileVersion': fts['FileVersionLength'] = length
                                    elif k == 'ProductName': fts['ProductNameLength'] = length
                                    elif k == 'ProductVersion': fts['ProductVersionLength'] = length
                                    elif k == 'CompanyName': fts['CompanyNameLength'] = length
                                    elif k == 'LegalCopyright': fts['LegalCopyrightLength'] = length
                                    elif k == 'Comments': fts['CommentsLength'] = length
                                    elif k == 'InternalName': fts['InternalNameLength'] = length
                                    elif k == 'LegalTrademarks': fts['LegalTrademarksLength'] = length
                                    elif k == 'SpecialBuild': fts['SpecialBuildLength'] = length
                                    elif k == 'PrivateBuild': fts['PrivateBuildLength'] = length
                                except Exception:
                                    continue

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            fts['ImportCount'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if getattr(entry, 'dll', None):
                    try:
                        dll_name = entry.dll.decode('ascii', 'ignore').lower()
                        if dll_name in Features.TARGET_DLLS: 
                            fts[f"Dll_{dll_name.replace('.', '_')}"] = 1.0
                    except Exception: 
                        pass
                
                imports = getattr(entry, 'imports', [])
                for imp in imports:
                    fts['ImportFunctionCount'] += 1.0
                    if not getattr(imp, 'name', None): continue
                    try:
                        func_name = imp.name.decode('ascii', 'ignore')
                        if func_name in Features._ALL_APIS:
                            fts[f'Api_{func_name}'] += 1.0
                            fts['ApiCount'] += 1.0
                        for cat in Features._API_TO_CATS.get(func_name, []):
                            fts[f'Cat_{cat}'] += 1.0
                    except Exception: 
                        continue

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and hasattr(pe.DIRECTORY_ENTRY_EXPORT, 'symbols'):
            fts['ExportCount'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if getattr(entry, 'id', None) == 3 and hasattr(entry, 'directory'):
                    fts['IconCount'] += len(getattr(entry.directory, 'entries', []))
                    
        if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 3:
            exc_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
            if exc_dir.Size > 0:
                fts['ExceptionCount'] = exc_dir.Size // 12 if fts['Machine'] in (0x8664, 0xAA64) else 0.0
            
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'): 
            fts['DebugCount'] = len(pe.DIRECTORY_ENTRY_DEBUG)

        for k in fts: 
            fts[k] = safe_float(fts[k])
            
        return fts

    except pefile.PEFormatError:
        return None
    except Exception:
        return None
    finally:
        if pe: 
            pe.close()

####################################################################################################

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA synchronous = OFF")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA cache_size = 10000")
    
    cols = "FileHash TEXT, " + ", ".join([f"{c} REAL" for c in Features.SCHEMA])
    conn.execute(f"CREATE TABLE IF NOT EXISTS PeData ({cols}, Label INTEGER)")
    conn.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS idx_pedata_hash ON PeData (FileHash)")
    conn.commit()
    return conn

def load_existing_hashes(conn):
    print("[*] Loading existing hashes into memory...")
    try:
        cursor = conn.execute("SELECT FileHash FROM PeData")
        return {row[0] for row in cursor.fetchall()}
    except:
        return set()

####################################################################################################

def scan_and_save(conn, path, label, existing_hashes):
    print(f"\n[*] Scanning: {path} (Label={label})")
    print(f"[*] Config: Max File Size = {MAX_FILE_SIZE/1024/1024:.0f} MB")
    
    files = []
    if os.path.isfile(path): 
        files.append(path)
    else:
        for r, _, fs in os.walk(path):
            for f in fs:
                if os.path.splitext(f)[1].lower() in TARGET_EXTENSIONS:
                    files.append(os.path.join(r, f))
    
    total = len(files)
    if total == 0:
        print("[-] No valid PE files found.")
        return

    print(f"[*] Found {total} files. Processing...\n")
    
    batch = []
    count = 0
    errors = 0
    skipped = 0
    start_time = time.time()
    
    placeholders = ",".join(["?"] * (len(Features.SCHEMA) + 2))
    sql = f"INSERT INTO PeData VALUES ({placeholders})"
    
    try:
        for i, file_path in enumerate(files):
            try:
                fsize = os.path.getsize(file_path)
                if fsize == 0 or fsize > MAX_FILE_SIZE:
                    errors += 1
                    continue

                with open(file_path, "rb") as f:
                    file_bytes = f.read()

                sha256 = hashlib.sha256(file_bytes).hexdigest()
                if sha256 in existing_hashes:
                    skipped += 1
                else:
                    res = process_single_file_content(file_bytes, file_path)
                    
                    if res:
                        vals = [sha256]
                        vals.extend([res.get(c, 0.0) for c in Features.SCHEMA])
                        vals.append(float(label))
                        batch.append(tuple(vals))
                        
                        existing_hashes.add(sha256)
                        count += 1
                    else:
                        errors += 1

            except Exception:
                errors += 1
            
            if len(batch) >= BATCH_SIZE:
                try:
                    conn.executemany(sql, batch)
                    conn.commit()
                    batch = []
                except Exception as batch_err:
                    print(f"\n[-] Batch Error: {batch_err}")
                    batch = []
            
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            sys.stdout.write(f"\r[{i+1}/{total}] New: {count} | Skip: {skipped} | Err: {errors} | {rate:.1f} files/s")
            sys.stdout.flush()

    except KeyboardInterrupt:
        print("\n\n[-] Interrupted by user.")
    except Exception as e:
        print(f"\n[-] Unexpected Error: {e}")
    finally:
        if batch:
            try:
                conn.executemany(sql, batch)
                conn.commit()
            except Exception:
                pass
        
        print(f"\n\n[+] Scan finished. Total New: {count}, Total Skipped: {skipped}")

####################################################################################################

if __name__ == "__main__":
    print("\n---------------- PE Dataset Builder v3.2 ----------------\n")
    
    if os.path.exists(DB_PATH):
        try:
            conn_check = sqlite3.connect(DB_PATH)
            cursor = conn_check.execute("PRAGMA table_info(PeData)")
            cols = [row[1] for row in cursor.fetchall()]
            if 'FileHash' not in cols or len(cols) != len(Features.SCHEMA) + 2:
                print(f"[-] WARNING: DB Schema mismatch. Please delete {DB_PATH} to rebuild.")
            conn_check.close()
        except: pass

    conn = init_db()
    
    existing_hashes = load_existing_hashes(conn)
    print(f"[+] Loaded {len(existing_hashes)} hashes from database.\n")

    try:
        while True:
            print("-" * 60)
            raw_path = input("\n[*] Enter Path (File or Folder): ").strip()
            target_path = raw_path.strip('"').strip("'")

            if target_path.lower() in ['exit', 'q']: break
            if not target_path or not os.path.exists(target_path):
                print("[-] Invalid path.")
                continue

            while True:
                label_input = input("[*] Enter Label (0=Safe, 1=Malware): ").strip()
                if label_input.lower() in ['exit', 'q']:
                    conn.close()
                    sys.exit()
                if label_input in ['0', '1']:
                    label = int(label_input)
                    break
                print("[-] Please enter 0 or 1.")

            scan_and_save(conn, target_path, label, existing_hashes)
            
    except KeyboardInterrupt:
        print("\n\n[-] Interrupted.")
    finally:
        conn.close()
        print(f"\n[+] Database saved to: {os.path.abspath(DB_PATH)}")
