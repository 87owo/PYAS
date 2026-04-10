import os, sys, time, re, math, pefile, json, datetime, mmap
import numpy as np
import onnxruntime as ort
from signify.authenticode.signed_file.pe import SignedPEFile
from signify.authenticode.verification_result import AuthenticodeVerificationResult

####################################################################################################

MODEL_FILE = "model.onnx"
FEATURE_FILE = "features.json"
MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024

####################################################################################################

class WinTrust:
    @staticmethod
    def verify(file_path):
        if not file_path or not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            return 0
        try:
            with open(file_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    pe = SignedPEFile(mm)
                    if not pe.signatures:
                        return 0

                    status, _ = pe.explain_verify()
                    if status == AuthenticodeVerificationResult.OK:
                        return 1
        except Exception:
            pass
        return 0

####################################################################################################

class FeatureExtractor:
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
        "CheckSum", "ImageBase", "SizeOfImage", "SizeOfHeaders",
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

    @staticmethod
    def _safe_float(val):
        try:
            f = float(val)
            if math.isinf(f) or math.isnan(f): return 0.0
            return f
        except Exception:
            return 0.0

    @staticmethod
    def _calc_entropy(data):
        if not data: return 0.0
        arr = np.frombuffer(data, dtype=np.uint8)
        counts = np.bincount(arr, minlength=256)
        probs = counts[counts > 0] / len(arr)
        return float(-np.sum(probs * np.log2(probs)))

    @staticmethod
    def _safe_div(n, d):
        return float(n) / d if d > 0 else 0.0

####################################################################################################

    @classmethod
    def extract(cls, file_path):
        fts = {k: 0.0 for k in cls.SCHEMA}
        pe = None
        try:
            fsize = os.path.getsize(file_path)
            if fsize == 0 or fsize > MAX_FILE_SIZE:
                return None

            with open(file_path, "rb") as f:
                file_bytes = f.read()

            pe = pefile.PE(data=file_bytes, fast_load=True)
            fts['TrustSigned'] = WinTrust.verify(file_path)

            fh = pe.FILE_HEADER
            fts['Machine'] = fh.Machine
            fts['NumberOfSections'] = fh.NumberOfSections
            fts['TimeDateStamp'] = fh.TimeDateStamp
            fts['PointerToSymbolTable'] = fh.PointerToSymbolTable
            fts['NumberOfSymbols'] = fh.NumberOfSymbols
            fts['SizeOfOptionalHeader'] = fh.SizeOfOptionalHeader
            fts['Characteristics'] = fh.Characteristics

            curr_ts = datetime.datetime.utcnow().timestamp()
            fts['HasInvalidTimestamp'] = 1 if (fh.TimeDateStamp < 631152000 or fh.TimeDateStamp > curr_ts + 2592000) else 0
            fts['FileTimeException'] = 1 if fh.TimeDateStamp == 0 else 0

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
                fts['Is64Bit'] = 1 if fh.Machine in (0x8664, 0xAA64, 0x0200) else 0
                fts['IsExe'] = 1 if pe.is_exe() else 0
                fts['IsDll'] = 1 if pe.is_dll() else 0
                fts['IsDriver'] = 1 if fts['Subsystem'] == 1 else 0

                if hasattr(op, 'DATA_DIRECTORY'):
                    reloc_idx = pefile.DIRECTORY_ENTRY.get('IMAGE_DIRECTORY_ENTRY_BASERELOC', 5)
                    if len(op.DATA_DIRECTORY) > reloc_idx and op.DATA_DIRECTORY[reloc_idx].Size > 0:
                        fts['HasRelocationDirectory'] = 1

            try:
                fts['FileEntropy'] = cls._calc_entropy(file_bytes)
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
                        s_entropy = cls._calc_entropy(s_data)
                    except Exception: 
                        s_data = b""
                        s_entropy = 0.0

                    sec_entropies.append(s_entropy)

                    if any(p in name.lower() for p in cls.PACKERS): fts['HasPacked'] = 1
                    if section.Characteristics & 0x20000000: fts['ExecutableSections'] += 1
                    if section.Characteristics & 0x80000000: fts['WritableSections'] += 1
                    if section.Characteristics & 0x40000000: fts['ReadableSections'] += 1
                    if section.SizeOfRawData + section.PointerToRawData > fsize: fts['SectionException'] = 1

                    for flag in char_flags:
                        if section.Characteristics & flag:
                            fts[f'Char_{flag:08X}_Count'] += 1
                            fts[f'Char_{flag:08X}_MeanEntropy'] += s_entropy

                    ratio = cls._safe_div(section.SizeOfRawData, fsize)
                    if name.startswith('.text'):
                        text_entropies.append(s_entropy)
                        fts['TextSizeRatio'] += ratio
                    elif name.startswith('.data'):
                        data_entropies.append(s_entropy)
                        fts['DataSizeRatio'] += ratio
                    elif name.startswith('.rsrc'):
                        rsrc_entropies.append(s_entropy)
                        fts['RsrcSizeRatio'] += ratio
                        if b"requireAdministrator" in s_data: fts['IsAdmin'] = 1
                        for sig in cls.INSTALLER_SIGS:
                            if sig in s_data:
                                fts['IsInstall'] = 1
                                break

            fts['SectionMeanEntropy'] = cls._safe_div(sum(sec_entropies), len(sec_entropies))
            fts['TextSectionMaxEntropy'] = max(text_entropies) if text_entropies else 0.0
            fts['TextSectionMeanEntropy'] = cls._safe_div(sum(text_entropies), len(text_entropies))
            fts['DataSectionMaxEntropy'] = max(data_entropies) if data_entropies else 0.0
            fts['DataSectionMeanEntropy'] = cls._safe_div(sum(data_entropies), len(data_entropies))
            fts['RsrcSectionMaxEntropy'] = max(rsrc_entropies) if rsrc_entropies else 0.0
            fts['RsrcSectionMeanEntropy'] = cls._safe_div(sum(rsrc_entropies), len(rsrc_entropies))

            for flag in char_flags:
                fts[f'Char_{flag:08X}_MeanEntropy'] = cls._safe_div(fts[f'Char_{flag:08X}_MeanEntropy'], fts[f'Char_{flag:08X}_Count'])

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
                    fts['HasTlsCallbacks'] = 1

            if hasattr(pe, 'VS_FIXEDFILEINFO') and len(pe.VS_FIXEDFILEINFO) > 0:
                flags = getattr(pe.VS_FIXEDFILEINFO[0], 'FileFlags', 0)
                fts['IsDebug'] = 1 if flags & 0x1 else 0
                fts['IsPreRelease'] = 1 if flags & 0x2 else 0
                fts['IsPatched'] = 1 if flags & 0x4 else 0
                fts['IsPrivateBuild'] = 1 if flags & 0x8 else 0
                fts['IsSpecialBuild'] = 1 if flags & 0x20 else 0

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
                            if dll_name in cls.TARGET_DLLS: 
                                fts[f"Dll_{dll_name.replace('.', '_')}"] = 1.0
                        except Exception: 
                            pass
                    
                    imports = getattr(entry, 'imports', [])
                    for imp in imports:
                        fts['ImportFunctionCount'] += 1
                        if not getattr(imp, 'name', None): continue
                        try:
                            func_name = imp.name.decode('ascii', 'ignore')
                            if func_name in cls._ALL_APIS:
                                fts[f'Api_{func_name}'] += 1
                                fts['ApiCount'] += 1
                            for cat in cls._API_TO_CATS.get(func_name, []):
                                fts[f'Cat_{cat}'] += 1
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
                    fts['ExceptionCount'] = exc_dir.Size // 12 if fts['Machine'] in (0x8664, 0xAA64) else 0
                
            if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'): 
                fts['DebugCount'] = len(pe.DIRECTORY_ENTRY_DEBUG)

            for k in fts: 
                fts[k] = cls._safe_float(fts[k])
                
            return fts

        except Exception:
            return None
        finally:
            if pe: 
                pe.close()

####################################################################################################

class ModelPredictor:
    def __init__(self, model_path, feature_path):
        self.sess = None
        self.input_name = None
        self.feature_order = [] 
        self.model_features = self._load_features(feature_path)
        self._load_model(model_path)
        self._build_input_map()

    def _load_features(self, path):
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return [re.sub(r'[^A-Za-z0-9_]+', '', f) for f in FeatureExtractor.SCHEMA]

    def _load_model(self, model_path):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model missing: {model_path}")

        self.sess = ort.InferenceSession(model_path, providers=['CPUExecutionProvider'])
        model_inputs = self.sess.get_inputs()
        self.input_name = model_inputs[0].name
        expected_dim = model_inputs[0].shape[1]
        
        current_dim = len(self.model_features)
        if current_dim != expected_dim:
            raise ValueError(f"Dimension Mismatch: Expected {expected_dim}, got {current_dim}.")

    def _build_input_map(self):
        local_map = {re.sub(r'[^A-Za-z0-9_]+', '', raw_name): raw_name for raw_name in FeatureExtractor.SCHEMA}
        self.feature_order = [local_map.get(req_feat) for req_feat in self.model_features]

    def predict(self, raw_data):
        vec_data = [raw_data.get(key, 0.0) if key else 0.0 for key in self.feature_order]
        vec = np.array(vec_data, dtype=np.float32).reshape(1, -1)
        outputs = self.sess.run(None, {self.input_name: vec})
        
        if len(outputs) > 1:
            result = outputs[1]
            if isinstance(result, list) and len(result) > 0:
                prob_dict = result[0]
                if hasattr(prob_dict, 'get'):
                    return float(prob_dict.get(1, prob_dict.get('1', 0.0)))
            elif isinstance(result, np.ndarray):
                if result.ndim == 2 and result.shape[1] > 1:
                    return float(result[0][1])
        return 0.0

####################################################################################################

def get_threat_name(prob_float):
    prob_pct = min(int(prob_float * 100), 99)
    
    if prob_pct >= 80:
        return f"General:WinPE/Malware.{prob_pct}!ml"
    elif prob_pct >= 50:
        return f"General:WinPE/Suspicious.{prob_pct}!ml"
    else:
        return "Undetected"

def scan_target(target, predictor):
    if not os.path.exists(target):
        print(json.dumps({"result": "error", "prob": 0.0, "file": target, "details": "Path not found"}))
        sys.stdout.flush()
        return

    try:
        data = FeatureExtractor.extract(target)
        if not data:
            print(json.dumps({"result": "error", "prob": 0.0, "file": target, "details": "Extraction failed"}))
            sys.stdout.flush()
            return
        
        prob = predictor.predict(data)
        label = get_threat_name(prob)
        
        print(json.dumps({"result": label, "prob": round(prob, 4), "file": target}))
        sys.stdout.flush()
        
    except Exception as e:
        print(json.dumps({"result": "error", "prob": 0.0, "file": target, "details": str(e)}))
        sys.stdout.flush()

####################################################################################################

if __name__ == "__main__":
    base_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_dir, MODEL_FILE)
    feature_path = os.path.join(base_dir, FEATURE_FILE)

    try:
        predictor = ModelPredictor(model_path, feature_path)
    except Exception as e:
        print(json.dumps({"result": "fatal", "details": str(e)}))
        sys.stdout.flush()
        sys.exit(1)

    if len(sys.argv) > 1:
        for path in sys.argv[1:]:
            scan_target(path.strip(), predictor)
    else:
        for line in sys.stdin:
            target = line.strip()
            if not target or target.lower() in ['q', 'exit']:
                break
            scan_target(target, predictor)
