import os, yara, time, numpy, base64, requests, pefile, math, json, re, datetime
import ctypes, ctypes.wintypes, hashlib, onnxruntime

from PIL import Image
from io import BytesIO

####################################################################################################

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.wintypes.DWORD),
        ("Data2", ctypes.wintypes.WORD),
        ("Data3", ctypes.wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8)]

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pcwszFilePath", ctypes.wintypes.LPCWSTR),
        ("hFile", ctypes.wintypes.HANDLE),
        ("pgKnownSubject", ctypes.wintypes.LPVOID)]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.wintypes.LPVOID),
        ("pSIPClientData", ctypes.wintypes.LPVOID),
        ("dwUIChoice", ctypes.wintypes.DWORD),
        ("fdwRevocationChecks", ctypes.wintypes.DWORD),
        ("dwUnionChoice", ctypes.wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", ctypes.wintypes.DWORD),
        ("hWVTStateData", ctypes.wintypes.HANDLE),
        ("pwszURLReference", ctypes.wintypes.LPCWSTR),
        ("dwProvFlags", ctypes.wintypes.DWORD),
        ("dwUIContext", ctypes.wintypes.DWORD),
        ("pSignatureSettings", ctypes.wintypes.LPVOID)]

####################################################################################################

class sign_scanner:
    def __init__(self):
        self.verify = GUID(0x00AAC56B, 0xCD44, 0x11D0, (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

    def init_windll(self, path):
        for name in path:
            try:
                setattr(self, name.lower(), ctypes.WinDLL(name, use_last_error=True))
            except Exception:
                pass

        try:
            self.WinVerifyTrust = self.wintrust.WinVerifyTrust
            self.WinVerifyTrust.restype = ctypes.wintypes.LONG
            self.WinVerifyTrust.argtypes = [ctypes.wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
        except Exception:
            pass

    def sign_verify(self, file_path):
        try:
            fi = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), file_path, None, None)
            td = WINTRUST_DATA(ctypes.sizeof(WINTRUST_DATA), None, None, 2, 0, 1, ctypes.pointer(fi), 1, None, None, 0, 0, None)
            return self.WinVerifyTrust(None, ctypes.byref(self.verify), ctypes.byref(td)) == 0
        except Exception:
            return False

####################################################################################################

class rule_scanner:
    def __init__(self):
        self.rules = None
        self.network = []

    def load_path(self, path, callback=None):
        yara_files = {}
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                if callback:
                    callback(full_path)
                ext = os.path.splitext(file)[1].lower()
                if ext in ('.yara', '.yar'):
                    namespace = os.path.relpath(full_path, path).replace(os.sep, '_')
                    yara_files[namespace] = full_path
                elif ext in ('.yc', '.yrc'):
                    self.load_compiled_rule(full_path)
                elif ext in ('.ip', '.txt'):
                    self.load_network_list(full_path)

        if yara_files:
            self.compile_all_rules(yara_files)

####################################################################################################

    def load_compiled_rule(self, file):
        try:
            self.rules = yara.load(file)
        except Exception:
            pass

    def load_network_list(self, file):
        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                self.network.extend(line.strip() for line in f if line.strip())
        except Exception:
            pass

    def compile_all_rules(self, file_map):
        try:
            self.rules = yara.compile(filepaths=file_map)
        except Exception:
            pass

####################################################################################################

    def yara_scan(self, file_path):
        try:
            if not self.rules:
                return False, False

            matches = self.rules.match(filepath=file_path)
            if matches:
                rule_name = str(matches[0])
                label = rule_name.split("_")[0]
                level = rule_name.split("_")[-1]
                return f"{label}:WinPE/Unknown.A!rb", level
            return False, False
        except Exception:
            return False, False

####################################################################################################

class cnn_scanner:
    def __init__(self):
        self.models = []
        self.labels = ["White:WinPE/Unknown", "General:WinPE/Unknown"]
        self.detect_set = {"General:WinPE/Unknown"}
        self.resize = (224, 224)

    def load_path(self, path, callback=None):
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                if callback:
                    callback(full_path)
                self.load_file(full_path)

    def load_file(self, file):
        if file.lower().endswith('.onnx'):
            try:
                session = onnxruntime.InferenceSession(file, providers=['CPUExecutionProvider'])
                self.models.append(session)
            except Exception:
                return False

####################################################################################################

    def model_scan(self, file_path, full_output=False):
        if not self.models:
            return (False, False) if not full_output else ([], str(file_path), None)

        data = self.get_data(file_path)
        if not data:
            return (False, False) if not full_output else ([], str(file_path), None)

        image = self.preprocess_image(data, self.resize)
        if not image:
            return (False, False) if not full_output else ([], str(file_path), None)

        arr = numpy.asarray(image).astype('float32') / 255.0
        arr = numpy.expand_dims(arr, axis=0)
        if arr.ndim == 3:
            arr = numpy.expand_dims(arr, axis=-1)

        results = []
        best_malicious = None

        for model in self.models:
            input_meta = model.get_inputs()[0]
            input_name = input_meta.name
            input_shape = input_meta.shape
            
            curr_arr = arr.copy()
            if len(input_shape) == 4:
                if input_shape[1] in (1, 3) and input_shape[3] not in (1, 3):
                    curr_arr = curr_arr.transpose(0, 3, 1, 2)
            
            try:
                probs = model.run(None, {input_name: curr_arr})[0]
                pred_prob = float(probs[0][0]) if hasattr(probs[0], '__len__') else float(probs[0])
            except Exception:
                continue

            is_malicious = pred_prob > 0.5
            idx = 1 if is_malicious else 0
            label = self.labels[idx]
            
            conf = pred_prob if is_malicious else (1.0 - pred_prob)
            conf = round(conf * 100, 2)

            if full_output:
                results.append(("Whole File", label, conf, self.pil_to_base64(image)))
            
            if label in self.detect_set:
                if best_malicious is None or conf > best_malicious[1]:
                    best_malicious = (f"{label}.{int(conf)}!dl", int(conf))

        if full_output:
            results.sort(key=lambda x: (x[1] not in self.detect_set, -x[2]))
            malicious_count = sum(1 for _, lbl, _, _ in results if lbl in self.detect_set)
            total = len(results)
            return results, str(file_path), f"{malicious_count}/{total}"

        return best_malicious if best_malicious else (False, False)

####################################################################################################

    def pil_to_base64(self, img):
        buf = BytesIO()
        img.save(buf, format='PNG')
        return base64.b64encode(buf.getvalue()).decode()

    def preprocess_image(self, data, size, channels=1):
        width, height = size
        wah = int(numpy.ceil(numpy.sqrt(len(data) / channels)))
        arr = numpy.frombuffer(data, dtype=numpy.uint8)
        imgbuf = numpy.zeros(wah * wah * channels, dtype=numpy.uint8)
        imgbuf[:len(arr)] = arr
        image = Image.fromarray(imgbuf.reshape((wah, wah)), 'L')
        return image.resize((width, height), Image.Resampling.NEAREST)

    def get_data(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception:
            return None

####################################################################################################

class pe_scanner:
    API_CAT_MAPPING = {
        'ProcessControl': {
            'CreateProcessA', 'CreateProcessW', 'WinExec', 'ShellExecuteA', 'ShellExecuteW',
            'ShellExecuteExW', 'ExitProcess', 'TerminateProcess', 'OpenProcess', 'GetExitCodeProcess',
            'SetThreadPriority', 'GetThreadPriority', 'GetCurrentProcess', 'GetCurrentProcessId'
        },
        'Injection': {
            'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx', 'WriteProcessMemory', 
            'ReadProcessMemory', 'CreateRemoteThread', 'QueueUserAPC', 'SetThreadContext', 'GetThreadContext', 
            'Wow64SetThreadContext', 'NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'RtlCreateUserThread', 
            'SetWindowsHookExA', 'SetWindowsHookExW', 'UnhookWindowsHookEx', 'LoadLibraryA', 'LoadLibraryW', 
            'LoadLibraryExA', 'LoadLibraryExW', 'GetProcAddress', 'GetModuleHandleA', 'GetModuleHandleW',
            'FreeLibrary', 'CreateFileMappingA', 'CreateFileMappingW', 'MapViewOfFile', 'UnmapViewOfSection'
        },
        'Synchronization': {
            'WaitForSingleObject', 'WaitForSingleObjectEx', 'WaitForMultipleObjects', 'WaitForMultipleObjectsEx',
            'CreateMutexA', 'CreateMutexW', 'OpenMutexW', 'ReleaseMutex', 'CreateEventA', 'CreateEventW', 
            'OpenEventW', 'SetEvent', 'ResetEvent', 'EnterCriticalSection', 'LeaveCriticalSection', 
            'InitializeCriticalSection', 'DeleteCriticalSection', 'Sleep', 'SleepEx'
        },
        'MultiThreading': {
            'CreateThread', 'ResumeThread', 'SuspendThread', 'ExitThread', 'TerminateThread',
            'GetCurrentThread', 'GetCurrentThreadId', 'TlsAlloc', 'TlsSetValue', 'TlsGetValue',
            'CreateThreadpoolWork', 'SubmitThreadpoolWork'
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
            'CryptDecodeObject', 'IsDBCSLeadByte', 'CharUpperA', 'CharLowerA'
        },
        'FileIO': {
            'CreateFileA', 'CreateFileW', 'WriteFile', 'ReadFile', 'DeleteFileA', 'DeleteFileW',
            'CopyFileA', 'CopyFileW', 'MoveFileA', 'MoveFileW', 'FindFirstFileA', 'FindNextFileA',
            'GetTempPathA', 'GetTempPathW', 'GetTempFileNameA', 'GetTempFileNameW', 'SetFileAttributesA', 
            'SetFileAttributesW', 'DeviceIoControl', 'SetFileTime', 'GetFileSize', 'GetFileSizeEx',
            'SetFilePointer', 'FlushFileBuffers', 'ConnectNamedPipe', 'PeekNamedPipe'
        },
        'Registry': {
            'RegOpenKeyExA', 'RegOpenKeyExW', 'RegSetValueExA', 'RegSetValueExW', 
            'RegCreateKeyExA', 'RegCreateKeyExW', 'RegDeleteKeyA', 'RegDeleteKeyW',
            'RegEnumValueA', 'RegEnumValueW', 'RegQueryValueExA', 'RegQueryValueExW',
            'RegDeleteValueA', 'RegDeleteValueW'
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
            'GetVersionExA', 'GetVersionExW', 'GetComputerNameA', 'GetComputerNameW'
        },
        'DotNet': {
            '_CorExeMain', '_CorDllMain'
        },
        'AntiDebug': {
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugStringA', 'OutputDebugStringW',
            'GetTickCount', 'GetTickCount64', 'QueryPerformanceCounter', 'FindWindowA', 'FindWindowW',
            'EnumWindows', 'EnumChildWindows', 'GetWindowRect', 'GetClientRect', 'SetWindowDisplayAffinity'
        },
        'Keylogging': {
            'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState', 'MapVirtualKeyA', 'MapVirtualKeyW',
            'ToAscii', 'ToAsciiEx', 'ToUnicode', 'ToUnicodeEx', 'GetKeyNameTextA', 'GetForegroundWindow',
            'KeybdEvent', 'SendInput', 'MapVirtualKeyExA', 'MapVirtualKeyExW'
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
        }
    }

    TARGET_DLLS = {
        'kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 'shell32.dll', 'ntdll.dll', 'hal.dll',
        'ws2_32.dll', 'wsock32.dll', 'wininet.dll', 'winhttp.dll', 'urlmon.dll', 'crypt32.dll', 'bcrypt.dll',
        'psapi.dll', 'dbghelp.dll', 'imagehlp.dll', 'shlwapi.dll', 'ole32.dll', 'oleaut32.dll', 'comctl32.dll',
        'mscoree.dll', 'vbscript.dll', 'netapi32.dll', 'iphlpapi.dll', 'wtsapi32.dll', 'version.dll', 'winmm.dll'
    }

    BASE_SCHEMA = [
        "FileEntropy", "IsExe", "IsDll", "IsDriver", "Is64Bit", "Machine", "Magic",
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
        "TextSection", "TextSizeRatio", "DataSection", "DataSizeRatio", 
        "RsrcSection", "RsrcSizeRatio", "SectionCount", "ExecutableSections", 
        "WritableSections", "ReadableSections", "SectionException",
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

    CAT_SCHEMA = [f"Cat_{k}" for k in API_CAT_MAPPING.keys()]
    DLL_SCHEMA = [f"Dll_{d.replace('.', '_')}" for d in sorted(TARGET_DLLS)]
    
    _ALL_APIS = {api for apis in API_CAT_MAPPING.values() for api in apis}
    API_SCHEMA = [f"Api_{api}" for api in sorted(_ALL_APIS)]
    
    SCHEMA = BASE_SCHEMA + CAT_SCHEMA + DLL_SCHEMA + API_SCHEMA
    
    API_REVERSE_MAP = {func: f"Cat_{cat}" for cat, funcs in API_CAT_MAPPING.items() for func in funcs}
    
    PACKERS = {
        'upx', 'aspack', 'asprotect', 'pecompact', 'upack', 'fsg', 'mew', 
        'mpress', 'ezip', 'pklt', 'shrink', 'petite', 'telock',
        'themida', 'winlicense', 'tmd', 'vmp', 'enigma', 'obsidium', 
        'pelock', 'exestealth', 'yoda', 'armadillo', 'zprotect',
        'sforce', 'starforce', 'qihoo', 'wisevec', 'megastop',
    }
    INSTALLER_SIGS = [b"Nullsoft.NSIS", b"Inno Setup", b"7-Zip.7zip", b"InstallShield"]

####################################################################################################

    def __init__(self):
        self.model = None
        self.input_name = None
        self.feature_order = []
        self.signer = sign_scanner()
        self.signer.init_windll(["wintrust"])

    def load_path(self, path, callback=None):
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                if callback:
                    callback(full_path)
                if full_path.endswith('.onnx'):
                    self.load_model(full_path)

    def load_model(self, model_path):
        if not os.path.exists(model_path):
            return
        try:
            self.model = onnxruntime.InferenceSession(model_path, providers=['CPUExecutionProvider'])
            self.input_name = self.model.get_inputs()[0].name
            
            feat_path = os.path.join(os.path.dirname(model_path), "features.json")
            model_features = []
            if os.path.exists(feat_path):
                with open(feat_path, 'r') as f:
                    model_features = json.load(f)
            else:
                model_features = [re.sub(r'[^A-Za-z0-9_]+', '', f) for f in self.SCHEMA]

            local_map = {re.sub(r'[^A-Za-z0-9_]+', '', raw_name): raw_name for raw_name in self.SCHEMA}
            self.feature_order = [local_map.get(req_feat) for req_feat in model_features]
        except Exception:
            pass

####################################################################################################

    def _safe_float(self, val):
        try:
            f = float(val)
            if math.isinf(f) or math.isnan(f): return 0.0
            return f
        except:
            return 0.0

    def _calc_entropy(self, data):
        if not data: return 0.0
        arr = numpy.frombuffer(data, dtype=numpy.uint8)
        counts = numpy.bincount(arr, minlength=256)
        probs = counts[counts > 0] / len(arr)
        return float(-numpy.sum(probs * numpy.log2(probs)))

####################################################################################################

    def extract_features(self, file_path):
        fts = {k: 0.0 for k in self.SCHEMA}
        pe = None
        try:
            fsize = os.path.getsize(file_path)
            if fsize == 0 or fsize > 268435456:
                return None

            with open(file_path, "rb") as f:
                file_bytes = f.read()

            pe = pefile.PE(data=file_bytes, fast_load=True)
            fts['TrustSigned'] = 1 if self.signer.sign_verify(file_path) else 0

            fh = pe.FILE_HEADER
            fts['Machine'] = fh.Machine
            fts['NumberOfSections'] = fh.NumberOfSections
            fts['TimeDateStamp'] = fh.TimeDateStamp
            fts['PointerToSymbolTable'] = fh.PointerToSymbolTable
            fts['NumberOfSymbols'] = fh.NumberOfSymbols
            fts['SizeOfOptionalHeader'] = fh.SizeOfOptionalHeader
            fts['Characteristics'] = fh.Characteristics

            curr_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()
            fts['HasInvalidTimestamp'] = 1 if (fh.TimeDateStamp < 631152000 or fh.TimeDateStamp > curr_ts + 2592000) else 0

            if hasattr(pe, 'OPTIONAL_HEADER'):
                op = pe.OPTIONAL_HEADER
                fts['Magic'] = op.Magic
                fts['MajorLinkerVersion'] = op.MajorLinkerVersion
                fts['MinorLinkerVersion'] = op.MinorLinkerVersion
                fts['SizeOfCode'] = op.SizeOfCode
                fts['SizeOfInitializedData'] = op.SizeOfInitializedData
                fts['SizeOfUninitializedData'] = op.SizeOfUninitializedData
                fts['AddressOfEntryPoint'] = op.AddressOfEntryPoint
                fts['BaseOfCode'] = op.BaseOfCode
                fts['ImageBase'] = op.ImageBase
                fts['SectionAlignment'] = op.SectionAlignment
                fts['FileAlignment'] = op.FileAlignment
                fts['MajorOperatingSystemVersion'] = op.MajorOperatingSystemVersion
                fts['MinorOperatingSystemVersion'] = op.MinorOperatingSystemVersion
                fts['MajorImageVersion'] = op.MajorImageVersion
                fts['MinorImageVersion'] = op.MinorImageVersion
                fts['MajorSubsystemVersion'] = op.MajorSubsystemVersion
                fts['MinorSubsystemVersion'] = op.MinorSubsystemVersion
                fts['SizeOfImage'] = op.SizeOfImage
                fts['SizeOfHeaders'] = op.SizeOfHeaders
                fts['CheckSum'] = op.CheckSum
                fts['Subsystem'] = op.Subsystem
                fts['DllCharacteristics'] = op.DllCharacteristics
                fts['SizeOfStackReserve'] = op.SizeOfStackReserve
                fts['SizeOfStackCommit'] = op.SizeOfStackCommit
                fts['SizeOfHeapReserve'] = op.SizeOfHeapReserve
                fts['SizeOfHeapCommit'] = op.SizeOfHeapCommit
                fts['LoaderFlags'] = op.LoaderFlags
                fts['NumberOfRvaAndSizes'] = op.NumberOfRvaAndSizes

                fts['Is64Bit'] = 1 if fh.Machine == 0x8664 else 0
                fts['IsExe'] = 1 if pe.is_exe() else 0
                fts['IsDll'] = 1 if pe.is_dll() else 0
                fts['IsDriver'] = 1 if pe.is_driver() else 0

                if len(op.DATA_DIRECTORY) > 9 and op.DATA_DIRECTORY[9].VirtualAddress > 0:
                    fts['HasTlsCallbacks'] = 1
                if len(op.DATA_DIRECTORY) > 5 and op.DATA_DIRECTORY[5].Size > 0:
                    fts['HasRelocationDirectory'] = 1

            pe.parse_sections(pe.FILE_HEADER.NumberOfSections)
            
            try:
                fts['FileEntropy'] = self._calc_entropy(file_bytes)
            except Exception:
                fts['FileEntropy'] = 0.0
                
            fts['SectionCount'] = len(pe.sections)

            for section in pe.sections:
                try:
                    name = section.Name.decode('ascii', 'ignore').strip('\x00')
                except Exception:
                    name = ""
                
                try:
                    s_data = section.get_data()
                    s_entropy = self._calc_entropy(s_data)
                except Exception:
                    s_data = b""
                    s_entropy = 0.0

                if any(p in name.lower() for p in self.PACKERS):
                    fts['HasPacked'] = 1
                if section.Characteristics & 0x20000000:
                    fts['ExecutableSections'] += 1
                if section.Characteristics & 0x80000000:
                    fts['WritableSections'] += 1
                if section.Characteristics & 0x40000000:
                    fts['ReadableSections'] += 1
                if section.SizeOfRawData + section.PointerToRawData > fsize:
                    fts['SectionException'] = 1

                ratio = section.SizeOfRawData / fsize if fsize > 0 else 0
                if name.startswith('.text'):
                    fts['TextSection'] = s_entropy
                    fts['TextSizeRatio'] = ratio
                elif name.startswith('.data'):
                    fts['DataSection'] = s_entropy
                    fts['DataSizeRatio'] = ratio
                elif name.startswith('.rsrc'):
                    fts['RsrcSection'] = s_entropy
                    fts['RsrcSizeRatio'] = ratio
                    if b"requireAdministrator" in s_data:
                        fts['IsAdmin'] = 1
                    for sig in self.INSTALLER_SIGS:
                        if sig in s_data:
                            fts['IsInstall'] = 1
                            break

            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']
            ])

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                fts['ImportCount'] = len(pe.DIRECTORY_ENTRY_IMPORT)
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    try:
                        dll_name = entry.dll.decode('ascii', 'ignore').lower()
                        if dll_name in self.TARGET_DLLS:
                            fts[f"Dll_{dll_name.replace('.', '_')}"] = 1.0
                    except Exception:
                        pass
                    
                    for imp in entry.imports:
                        fts['ImportFunctionCount'] += 1
                        if not imp or not hasattr(imp, 'name') or not imp.name:
                            continue
                        try:
                            func_name = imp.name.decode('ascii', 'ignore')
                            if func_name in self._ALL_APIS:
                                fts[f'Api_{func_name}'] += 1
                                
                            cat_key = self.API_REVERSE_MAP.get(func_name)
                            if cat_key:
                                fts[cat_key] += 1
                        except Exception:
                            pass

            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                fts['ExportCount'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if entry.id == 3 and hasattr(entry, 'directory'):
                        fts['IconCount'] = len(entry.directory.entries)
                        break
            
            if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                fts['DebugCount'] = len(pe.DIRECTORY_ENTRY_DEBUG)

            return {k: self._safe_float(v) for k, v in fts.items()}

        except Exception:
            return None
        finally:
            if pe:
                pe.close()

####################################################################################################

    def pe_scan(self, file_path):
        if not self.model:
            return False, False
        
        try:
            data = self.extract_features(file_path)
            if not data:
                return False, False

            vec_data = []
            for key in self.feature_order:
                if key:
                    vec_data.append(data.get(key, 0.0))
                else:
                    vec_data.append(0.0)
                    
            vec = numpy.array(vec_data, dtype=numpy.float32).reshape(1, -1)
            outputs = self.model.run(None, {self.input_name: vec})
            
            result = outputs[1]
            prob = 0.0
            if isinstance(result, list) and len(result) > 0:
                prob_dict = result[0]
                if hasattr(prob_dict, 'get'):
                    prob = float(prob_dict.get(1, prob_dict.get('1', 0.0)))
            elif isinstance(result, numpy.ndarray):
                if result.ndim == 2 and result.shape[1] > 1:
                    prob = float(result[0][1])

            score = int(prob * 100)
            if prob > 0.5:
                return f"General:WinPE/Unknown.{score}!ml", score
            
            return False, False

        except Exception:
            return False, False

####################################################################################################

class cloud_scanner:
    def __init__(self):
        pass

    def calc_hash(self, file_path, block_size=65536):
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(block_size), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

####################################################################################################

    def upload_file(self, file_path, api_host, api_key):
        try:
            sha256 = self.calc_hash(file_path)
            if not sha256:
                return False, None

            base = api_host.rstrip('/')
            base_headers = {"X-API-Key": api_key, "User-Agent": "PYAS-Client/1.0"}

            def _req(m, ep, files=None, **k):
                try:
                    return requests.request(m, f"{base}{ep}", headers=base_headers, files=files, timeout=120, **k)
                except:
                    return None

            r = _req("GET", f"/api/processing_status/{sha256}")
            status = r.json().get('status') if r and r.status_code == 200 else 'missing'
            if status in ['failed', 'error']:
                status = 'missing'

            if status == 'missing':
                with open(file_path, 'rb') as f:
                    r = _req("POST", "/api/upload", files={'file': f})
                    if not r or r.status_code != 200:
                        return False, sha256

            return True, sha256
        except Exception:
            return False, None

####################################################################################################

    def get_result(self, sha256, api_host, api_key):
        try:
            if not sha256:
                return False

            base = api_host.rstrip('/')
            headers = {"X-API-Key": api_key, "User-Agent": "PYAS-Client/1.0"}

            def _req(m, ep, **k):
                try:
                    return requests.request(m, f"{base}{ep}", headers=headers, timeout=10, **k)
                except:
                    return None

            for _ in range(30):
                r = _req("GET", f"/api/processing_status/{sha256}")
                st = r.json().get('status') if r else 'error'
                if st == 'done':
                    break
                if st in ['error', 'failed']:
                    return False
                time.sleep(1)

            r = _req("GET", f"/api/report/{sha256}")
            if r and r.status_code == 200:
                data = r.json().get('data', {})
                res = data.get('detection', {}).get('results', {}).get('PYAS', {})
                label = res.get('label', 'Unsupport')
                score = res.get('score', 100)
                sims = data.get('similar', [])

                is_malicious = 'General' in label
                sim_malicious_count = 0
                valid_sim_count = 0
                for s in sims:
                    if s.get('similarity', 0) > 80:
                        valid_sim_count += 1
                        if "General" in s.get('label', ''):
                            sim_malicious_count += 1

                if is_malicious and (valid_sim_count == 0 or sim_malicious_count == valid_sim_count):
                    return f"General:WinPE/Unknown.{score}!cl"
        except Exception:
            pass
        return False
