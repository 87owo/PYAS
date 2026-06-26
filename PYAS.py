import os, re, gc, io, csv, sys, time, json, uuid, stat, queue, msvcrt
import shutil, hashlib, platform, threading, subprocess, pefile, winreg
import pystray, requests, webview, webbrowser, ctypes, ctypes.wintypes

from PIL import Image
from concurrent.futures import ThreadPoolExecutor
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from webview.dom import DOMEventHandler

from PYAS_Engine import sign_scanner, rule_scanner, pe_scanner, cloud_scanner

####################################################################################################

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
        ("szExeFile", ctypes.wintypes.WCHAR * 260)
    ]

class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.wintypes.DWORD),
        ("dwLocalAddr", ctypes.wintypes.DWORD),
        ("dwLocalPort", ctypes.wintypes.DWORD),
        ("dwRemoteAddr", ctypes.wintypes.DWORD),
        ("dwRemotePort", ctypes.wintypes.DWORD),
        ("dwOwningPid", ctypes.wintypes.DWORD)
    ]

class FILE_NOTIFY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset", ctypes.wintypes.DWORD),
        ("Action", ctypes.wintypes.DWORD),
        ("FileNameLength", ctypes.wintypes.DWORD),
        ("FileName", ctypes.wintypes.WCHAR * 1024)
    ]

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.wintypes.LPVOID),
        ("PebBaseAddress", ctypes.wintypes.LPVOID),
        ("Reserved2", ctypes.wintypes.LPVOID * 2),
        ("UniqueProcessId", ctypes.wintypes.LPVOID),
        ("Reserved3", ctypes.wintypes.LPVOID)
    ]

class SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.wintypes.DWORD),
        ("i64Size", ctypes.c_int64),
        ("i64NumItems", ctypes.c_int64)
    ]

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.wintypes.USHORT),
        ("MaximumLength", ctypes.wintypes.USHORT),
        ("Buffer", ctypes.c_void_p)
    ]

class FILTER_MESSAGE_HEADER(ctypes.Structure):
    _fields_ = [
        ("ReplyLength", ctypes.wintypes.ULONG),
        ("MessageId", ctypes.c_uint64)
    ]

class PYAS_MESSAGE(ctypes.Structure):
    _fields_ = [
        ("MessageCode", ctypes.wintypes.ULONG),
        ("ProcessId", ctypes.wintypes.ULONG),
        ("Path", ctypes.wintypes.WCHAR * 1024)
    ]

class PYAS_FULL_MESSAGE(ctypes.Structure):
    _fields_ = [
        ("Header", FILTER_MESSAGE_HEADER),
        ("Data", PYAS_MESSAGE)
    ]

class PYAS_USER_MESSAGE(ctypes.Structure):
    _fields_ = [
        ("Command", ctypes.wintypes.ULONG),
        ("Path", ctypes.wintypes.WCHAR * 1024)
    ]

class COPYDATASTRUCT(ctypes.Structure):
    _fields_ = [
        ("dwData", ctypes.c_size_t),
        ("cbData", ctypes.wintypes.DWORD),
        ("lpData", ctypes.c_void_p)
    ]

class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong)
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.wintypes.DWORD),
        ("Protect", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD)
    ]

####################################################################################################

class WindowAPI:
    def __init__(self):
        self._window = None
        self.lock_config = threading.RLock()
        self.lock_logs = threading.RLock()
        self.lock_virus = threading.RLock()
        self.lock_file_ops = threading.RLock()
        
        self.init_environ()
        self.init_windll()
        
        if not self.check_singleton("PYAS_Security_Mutex"):
            hwnd = self.user32.FindWindowW(None, "PYAS Security")
            if hwnd:
                if "-quit" in self.args_pyas:
                    try:
                        cds = COPYDATASTRUCT()
                        cds.dwData = 3
                        cds.cbData = 0
                        cds.lpData = None
                        self.user32.SendMessageTimeoutW(hwnd, 0x004A, 0, ctypes.byref(cds), 0x0002, 3000, None)

                        time.sleep(0.5)
                    except Exception:
                        pass

                elif "-scan" in self.args_pyas:
                    try:
                        idx = self.args_pyas.index("-scan")
                        target = self.args_pyas[idx+1]
                        cds = COPYDATASTRUCT()
                        cds.dwData = 1
                        encoded = target.encode('utf-8')
                        cds.cbData = len(encoded) + 1
                        buffer = ctypes.create_string_buffer(encoded)
                        cds.lpData = ctypes.cast(buffer, ctypes.c_void_p)
                        self.user32.SendMessageTimeoutW(hwnd, 0x004A, 0, ctypes.byref(cds), 0x0002, 3000, None)
                        self.user32.SetForegroundWindow(hwnd)

                    except Exception:
                        pass
                else:
                    try:
                        cds = COPYDATASTRUCT()
                        cds.dwData = 2
                        cds.cbData = 0
                        cds.lpData = None
                        self.user32.SendMessageTimeoutW(hwnd, 0x004A, 0, ctypes.byref(cds), 0x0002, 3000, None)
                        self.user32.SetForegroundWindow(hwnd)

                    except Exception:
                        pass
            os._exit(0)
            
        if "-quit" in self.args_pyas:
            os._exit(0)
            
        self.init_variables()
        self.load_config()
        self.load_logs()

    def check_singleton(self, name):
        try:
            self.h_mutex = self.kernel32.CreateMutexW(None, False, name)
            if ctypes.get_last_error() == 183:
                return False

            return True
        except Exception:
            return False

    def init_environ(self):
        self.python = sys.executable
        if getattr(sys, 'frozen', False):
            self.file_pyas = self.norm_path(sys.executable)
        else:
            self.file_pyas = self.norm_path(os.path.abspath(sys.argv[0]))
            
        self.args_pyas = sys.argv[1:]
        self.path_pyas = os.path.dirname(self.file_pyas)
        self.pid_pyas = int(os.getpid())
        
        self.path_appdata = os.environ.get("APPDATA")
        self.path_name = os.environ.get("USERNAME")
        self.path_temp = os.environ.get("TEMP", f"C:\\Users\\{self.path_name}\\AppData\\Local\\Temp")
        self.path_config = os.environ.get("ALLUSERSPROFILE", "C:\\ProgramData")
        self.path_system = os.environ.get("SYSTEMROOT", "C:\\Windows")
        self.path_user = os.environ.get("USERPROFILE", f"C:\\Users\\{self.path_name}")
        
        self.path_systemp = os.path.join(self.path_system, "Temp")
        self.file_config = os.path.join(self.path_config, "PYAS", "Config.json")
        self.file_log = os.path.join(self.path_config, "PYAS", "Report.json")
        self.path_properties = os.path.join(self.path_pyas, "Engine", "Properties")
        self.path_heuristic = os.path.join(self.path_pyas, "Engine", "Heuristic")
        self.path_protect = os.path.join(self.path_pyas, "Plugins", "Filter")
        self.path_drivers = os.path.join(self.path_protect, "PYAS_Driver.sys")

    def init_windll(self):
        for name in ["ntdll", "Psapi", "user32", "kernel32", "iphlpapi", "shell32", "fltlib"]:
            try:
                setattr(self, name.lower(), ctypes.WinDLL(name, use_last_error=True))
            except Exception as e:
                self.write_log("WARN", "init_windll", detail=str(e), success=False)
        
        self.user32.FindWindowW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
        self.user32.FindWindowW.restype = ctypes.wintypes.HWND
        self.user32.ShowWindow.argtypes = [ctypes.wintypes.HWND, ctypes.c_int]
        self.user32.ShowWindow.restype = ctypes.wintypes.BOOL
        self.user32.SendMessageTimeoutW.argtypes = [ctypes.wintypes.HWND, ctypes.wintypes.UINT, ctypes.wintypes.WPARAM, ctypes.c_void_p, ctypes.wintypes.UINT, ctypes.wintypes.UINT, ctypes.c_void_p]
        self.user32.SendMessageTimeoutW.restype = ctypes.wintypes.LPARAM

        self.ntdll.NtQueryInformationProcess.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.ULONG, ctypes.c_void_p, ctypes.wintypes.ULONG, ctypes.POINTER(ctypes.wintypes.ULONG)]
        self.ntdll.NtQueryInformationProcess.restype = ctypes.wintypes.ULONG
        self.ntdll.NtSuspendProcess.argtypes = [ctypes.wintypes.HANDLE]
        self.ntdll.NtSuspendProcess.restype = ctypes.c_ulong
        self.ntdll.NtResumeProcess.argtypes = [ctypes.wintypes.HANDLE]
        self.ntdll.NtResumeProcess.restype = ctypes.c_ulong

        self.shell32.CommandLineToArgvW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
        self.shell32.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.wintypes.LPWSTR)
        self.shell32.SHEmptyRecycleBinW.argtypes = [ctypes.wintypes.HWND, ctypes.c_wchar_p, ctypes.wintypes.DWORD]
        self.shell32.SHEmptyRecycleBinW.restype = ctypes.c_long
        self.shell32.SHQueryRecycleBinW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(SHQUERYRBINFO)]
        self.shell32.SHQueryRecycleBinW.restype = ctypes.c_long

        self.fltlib.FilterConnectCommunicationPort.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(ctypes.wintypes.HANDLE)]
        self.fltlib.FilterConnectCommunicationPort.restype = ctypes.c_long
        self.fltlib.FilterGetMessage.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.c_void_p]
        self.fltlib.FilterGetMessage.restype = ctypes.c_long
        self.fltlib.FilterSendMessage.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD)]
        self.fltlib.FilterSendMessage.restype = ctypes.c_long

        self.kernel32.CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE
        self.kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]
        self.kernel32.Process32FirstW.restype = ctypes.wintypes.BOOL
        self.kernel32.Process32FirstW.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p]
        self.kernel32.Process32NextW.restype = ctypes.wintypes.BOOL
        self.kernel32.Process32NextW.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p]
        self.kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE
        self.kernel32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
        self.kernel32.CloseHandle.restype = ctypes.wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
        self.kernel32.TerminateProcess.restype = ctypes.wintypes.BOOL
        self.kernel32.TerminateProcess.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_uint]
        self.kernel32.CreateMutexW.restype = ctypes.wintypes.HANDLE
        self.kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.wintypes.BOOL, ctypes.c_wchar_p]
        self.kernel32.CreateFileW.restype = ctypes.wintypes.HANDLE
        self.kernel32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.HANDLE]
        self.kernel32.ReadProcessMemory.restype = ctypes.wintypes.BOOL
        self.kernel32.ReadProcessMemory.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.kernel32.QueryFullProcessImageNameW.restype = ctypes.wintypes.BOOL
        self.kernel32.QueryFullProcessImageNameW.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.c_wchar_p, ctypes.POINTER(ctypes.wintypes.DWORD)]
        self.kernel32.GetProcessIoCounters.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(IO_COUNTERS)]
        self.kernel32.GetProcessIoCounters.restype = ctypes.wintypes.BOOL
        self.kernel32.VirtualQueryEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
        self.kernel32.VirtualQueryEx.restype = ctypes.c_size_t
        self.kernel32.SetProcessWorkingSetSize.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_size_t, ctypes.c_size_t]
        self.kernel32.SetProcessWorkingSetSize.restype = ctypes.wintypes.BOOL
        
        self.psapi.GetMappedFileNameW.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.wintypes.LPWSTR, ctypes.wintypes.DWORD]
        self.psapi.GetMappedFileNameW.restype = ctypes.wintypes.DWORD

    def init_variables(self):
        self.python = sys.executable

        self.heuristic = rule_scanner()
        self.properties = pe_scanner()
        self.cloud = cloud_scanner()
        self.cloud_queue = queue.Queue()
        
        self.ui_queue = queue.Queue()
        self.start_daemon_thread(self.ui_dispatcher_thread)
        
        self.tray_icon = None
        self.driver_port = None
        self.engine_initialized = False
        self.logs_dirty = False
        self.scan_running = False
        self.scan_finished = False
        self.virus_lock = {}
        self.virus_results = []
        self.scan_count = 0
        self.scan_events = {}
        self.hash_cache = {}
        self.mbr_backup = {}
        self.logs_data = []
        self.cloud_pending = set()
        self.last_io_counters = {}
        self.last_io_time = time.time()
        self.suspended_procs = set()
        
        self.lock_driver = threading.RLock()
        self.lock_update = threading.RLock()
        self.lock_proc = threading.RLock()
        self.lock_net = threading.RLock()
        self.lock_file_ops = threading.RLock()
        self.lock_io = threading.RLock()
        
        self.pyas_default = {
            "version": "3.6.1",
            "api_host": "https://pyas-security.com/",
            "api_key": "fBRZxYS1UxykM-qzNOlKOEl63WILzlvgNMn6QfsG6FXCAAIktCrOPTAfY5_hEyuZ",
            "suffix": [".exe", ".dll", ".sys", ".ocx", ".scr", ".efi", ".acm", ".ax", ".cpl", ".drv", ".com", ".mui", ".pyd", ".wfx", ".api", ".awx", ".rll", ".winmd"],
            "block": [2001, 3001, 5001, 6001],
            "size": 256 * 1024 * 1024,
            "language": "english_switch",
            "theme": "system_switch",
            "first_launch": True,
            "process_switch": False,
            "suspend_switch": True,
            "document_switch": False,
            "system_switch": False,
            "driver_switch": False,
            "network_switch": False,
            "extension_switch": False,
            "sensitive_switch": False,
            "cloud_switch": False,
            "suffix_switch": True,
            "autostart_switch": True,
            "context_switch": True,
            "custom_rule": [],
            "white_list": [],
            "quarantine": [],
            "block_list": []
        }
        
        self.pass_windows = [
            {"exe": "System Idle Process", "class": "", "title": ""},
            {"exe": "", "class": "Windows.UI.Core.CoreWindow", "title": ""},
            {"exe": "explorer.exe", "class": "", "title": ""}
        ]
        
        self.scan_pool = ThreadPoolExecutor(max_workers=2)
        self.protect_pool = ThreadPoolExecutor(max_workers=8)
        self.proc_pool = ThreadPoolExecutor(max_workers=16)
        self.start_daemon_thread(self.log_flush_thread)

        for _ in range(2):
            self.start_daemon_thread(self.cloud_worker)

    def ui_dispatcher_thread(self):
        batch = []
        while True:
            try:
                task = self.ui_queue.get(timeout=0.1)
                batch.append(task)
                
                while not self.ui_queue.empty() and len(batch) < 50:
                    try:
                        batch.append(self.ui_queue.get_nowait())
                    except queue.Empty:
                        break

                if self._window and batch:
                    js_script = "".join(batch)
                    try:
                        self._window.evaluate_js(js_script)
                    except Exception:
                        pass

                for _ in batch:
                    self.ui_queue.task_done()
                batch.clear()

            except queue.Empty:
                continue
            except Exception:
                batch.clear()

    def _loc(self, text_dict):
        with self.lock_config:
            lang = self.pyas_config.get("language", "traditional_switch") if hasattr(self, 'pyas_config') else "traditional_switch"
        return text_dict.get(lang, text_dict.get("traditional_switch", ""))

    def _reg_read(self, root, path, value_name):
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as reg:
                val, _ = winreg.QueryValueEx(reg, value_name)
                return val

        except Exception:
            return None

    def _reg_write(self, root, path, value_name, value_type, value):
        try:
            with winreg.CreateKey(root, path) as reg:
                if value_name is None:
                    winreg.SetValue(reg, "", value_type, value)
                else:
                    winreg.SetValueEx(reg, value_name, 0, value_type, value)
                return True

        except Exception:
            return False

    def _reg_delete(self, root, path, value_name=None):
        try:
            if value_name is None:
                winreg.DeleteKey(root, path)
            else:
                with winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WRITE) as reg:
                    winreg.DeleteValue(reg, value_name)

            return True
        except Exception:
            return False

    def load_config(self):
        with self.lock_config:

            if not os.path.exists(self.file_config):
                self.pyas_config = self.pyas_default.copy()
                self.write_log("INFO", "Config Update", detail="Create default config")
                self.save_config()
            else:
                try:
                    with open(self.file_config, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        self.pyas_config = {**self.pyas_default, **data}
                    self.pyas_config["version"] = self.pyas_default["version"]

                except Exception as e:
                    self.pyas_config = self.pyas_default.copy()
                    self.write_log("WARN", "load_config", detail=str(e), success=False)

    def save_config(self):
        with self.lock_config:
            try:
                os.makedirs(os.path.dirname(self.file_config), exist_ok=True)
                with open(self.file_config, "w", encoding="utf-8") as f:
                    json.dump(self.pyas_config, f, indent=4, ensure_ascii=False)

            except Exception as e:
                self.write_log("WARN", "save_config", detail=str(e), success=False)

    def update_config(self, key, value):
        with self.lock_update:
            with self.lock_config:
                old_value = self.pyas_config.get(key)
                if old_value == value:
                    return value
                self.pyas_config[key] = value

            if key in ["extension_switch", "sensitive_switch"]:
                with self.lock_file_ops:
                    if hasattr(self, 'hash_cache'):
                        self.hash_cache.clear()

            success = True
            if value:
                try:
                    if key == "process_switch":
                        self.start_daemon_thread(self.protect_proc_thread)
                    elif key == "document_switch":
                        self.start_daemon_thread(self.protect_file_thread)
                    elif key == "system_switch":
                        self.start_daemon_thread(self.protect_system_thread)
                    elif key == "network_switch":
                        self.start_daemon_thread(self.protect_net_thread)
                    elif key == "driver_switch":
                        if self.install_system_driver():
                            self.start_daemon_thread(self.pipe_server_thread)
                        else:
                            success = False
                    elif key == "context_switch":
                        self.register_context_menu(True)
                    elif key == "autostart_switch":
                        self.manage_autostart(True)

                except Exception as e:
                    self.write_log("WARN", "Feature Start", detail=str(e), success=False)
                    success = False
            else:
                if key == "driver_switch":
                    success = self.stop_system_driver()
                elif key == "context_switch":
                    self.register_context_menu(False)
                elif key == "document_switch":
                    with self.lock_file_ops:
                        if getattr(self, 'h_dir_file', None):
                            try:
                                self.kernel32.CloseHandle(self.h_dir_file)
                            except Exception:
                                pass
                            self.h_dir_file = None
                elif key == "autostart_switch":
                    self.manage_autostart(False)
                elif key == "suspend_switch":
                    with self.lock_proc:
                        if hasattr(self, 'suspended_procs'):
                            for h in list(self.suspended_procs):
                                try:
                                    self.ntdll.NtResumeProcess(h)
                                except Exception:
                                    pass
                            self.suspended_procs.clear()

            if success:
                with self.lock_config:
                    self.write_log("INFO", "Config Update", detail=f"[{key}] {old_value} -> {value}")
                    self.save_config()

                if key == "language" and self.tray_icon:
                    try:
                        self.tray_icon.update_menu()
                    except Exception:
                        pass

                return value
            else:
                with self.lock_config:
                    self.pyas_config[key] = old_value
                if self._window:
                    self._window.evaluate_js(f"if(window.revertSwitch) window.revertSwitch('{key}');")

                return old_value

    def get_config(self):
        with self.lock_config:
            return self.pyas_config.copy()

    def reset_config(self):
        with self.lock_config:
            self.pyas_config = self.pyas_default.copy()
            self.write_log("INFO", "Config Update", detail="Reset to default")
            self.save_config()

        return True

    def load_logs(self):
        with self.lock_logs:
            if os.path.exists(self.file_log):
                try:
                    with open(self.file_log, "r", encoding="utf-8") as f:
                        self.logs_data = json.load(f)

                except Exception:
                    self.logs_data = []

    def log_flush_thread(self):
        while True:
            time.sleep(5)
            with self.lock_logs:
                if getattr(self, 'logs_dirty', False):
                    try:
                        os.makedirs(os.path.dirname(self.file_log), exist_ok=True)
                        with open(self.file_log, "w", encoding="utf-8") as f:
                            json.dump(self.logs_data, f, indent=4, ensure_ascii=False)

                        self.logs_dirty = False
                    except Exception:
                        pass

    def write_log(self, level, action, detail=None, code=None, pid=None, file_hash=None, source=None, target=None, operate=None, success=True):
        with self.lock_logs:
            entry = {
                "id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "time_str": time.strftime("%Y-%m-%d %H:%M:%S"),
                "level": level,
                "action": action,
                "detail": detail,
                "code": code,
                "pid": pid,
                "hash": file_hash,
                "source": source,
                "target": target,
                "operate": operate,
                "success": success
            }
            self.logs_data.append(entry)
            
            if len(self.logs_data) > 1000:
                self.logs_data = self.logs_data[-1000:]
            self.logs_dirty = True

            if self._window:
                js_cmd = f"if(window.updateLogs) window.updateLogs({json.dumps(entry)});"
                self.ui_queue.put(js_cmd)

        if level == "BLOCK" and self.tray_icon:
            self.trigger_block_notification(action, source, target, code)

    def get_logs(self):
        with self.lock_logs:
            return self.logs_data.copy()

    def clear_logs(self, log_ids=None):
        with self.lock_logs:
            if log_ids is None:
                self.logs_data = []
            else:
                self.logs_data = [log for log in self.logs_data if log['id'] not in log_ids]

            try:
                if not self.logs_data:
                    if os.path.exists(self.file_log):
                        os.remove(self.file_log)
                else:
                    os.makedirs(os.path.dirname(self.file_log), exist_ok=True)
                    with open(self.file_log, "w", encoding="utf-8") as f:
                        json.dump(self.logs_data, f, indent=4, ensure_ascii=False)

            except Exception:
                pass

    def export_logs(self, log_ids=None):
        if self._window:
            path = self._window.create_file_dialog(webview.FileDialog.SAVE, directory='', save_filename='PYAS_Logs.json')
            if path:
                target_path = path[0] if isinstance(path, (tuple, list)) else path

                with self.lock_logs:
                    export_data = self.logs_data
                    if log_ids is not None:
                        export_data = [log for log in self.logs_data if log['id'] in log_ids]

                    try:
                        with open(target_path, 'w', encoding='utf-8') as f:
                            json.dump(export_data, f, indent=4, ensure_ascii=False)

                        return True
                    except Exception:
                        pass
        return False

    def manage_autostart(self, enable):
        try:
            task_name = "PYAS_Security_ATS"
            if enable:
                cmd = f"$Action = New-ScheduledTaskAction -Execute '{self.file_pyas}' -Argument '-hide'; $Trigger = New-ScheduledTaskTrigger -AtLogOn; $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName '{task_name}' -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel Highest -Force"
                subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", cmd], creationflags=0x08000000)
            else:
                subprocess.run(["schtasks", "/Delete", "/TN", task_name, "/F"], creationflags=0x08000000)

            return True
        except Exception as e:
            self.write_log("WARN", "manage_autostart", detail=str(e), success=False)
            return False

    def manage_named_list(self, list_key, files, action="add", lock_func=None):
        if list_key == "quarantine" and lock_func is None:
            lock_func = self.lock_file

        norm_paths = self.norm_path(files or [], must_exist=False)
        if isinstance(norm_paths, str):
            norm_paths = [norm_paths] if norm_paths else []

        if not norm_paths:
            return 0

        if action == "add":
            if list_key == "white_list":
                self.remove_list_items("quarantine", norm_paths)
            elif list_key == "quarantine":
                self.remove_list_items("white_list", norm_paths)

        acted_items = []
        with self.lock_config:
            target_list = self.pyas_config.setdefault(list_key, [])
            if action == "add":
                for path in norm_paths:
                    path_case = os.path.normcase(path)
                    exists = False

                    for item in target_list:
                        val = item.get("file", "") if isinstance(item, dict) else item
                        np = self.norm_path(val, must_exist=False)

                        if np and os.path.normcase(np) == path_case:
                            exists = True
                            break

                    if not exists:
                        if lock_func:
                            lock_func(path, True)

                        target_list.append({"file": path, "time": time.time()})
                        acted_items.append(path)
                        if list_key == "white_list":
                            self.sync_driver_whitelist(path, True)

            elif action == "remove":
                norm_paths_case = {os.path.normcase(p) for p in norm_paths}
                new_list = []
                for item in target_list:
                    val = item.get("file", "") if isinstance(item, dict) else item
                    if val:
                        np = self.norm_path(val, must_exist=False)
                        if np and os.path.normcase(np) in norm_paths_case:
                            if lock_func:
                                lock_func(val, False)

                            acted_items.append(val)
                            if list_key == "white_list":
                                self.sync_driver_whitelist(val, False)

                            continue
                    new_list.append(item)
                target_list[:] = new_list

            if acted_items:
                self.write_log("INFO", "Config Update", detail=f"List [{list_key}] {action}: {acted_items}")
                self.save_config()

        return len(acted_items)

    def remove_list_items(self, list_key, paths_to_remove):
        with self.lock_config:
            target_list = self.pyas_config.get(list_key, [])
            original_len = len(target_list)
            
            norm_paths_to_remove = set()
            for p in paths_to_remove:
                np = self.norm_path(p, must_exist=False)
                if np:
                    norm_paths_to_remove.add(os.path.normcase(np))
            
            if list_key == "quarantine":
                for item in target_list:
                    val = item.get("file") if isinstance(item, dict) else item
                    if val:
                        np = self.norm_path(val, must_exist=False)
                        if np and os.path.normcase(np) in norm_paths_to_remove:
                            self.lock_file(val, False)
            
            new_list = []
            removed_items = []
            for item in target_list:
                val = item.get("file") or item.get("exe") or item.get("title") if isinstance(item, dict) else item
                if val:
                    np = self.norm_path(val, must_exist=False)
                    if np and os.path.normcase(np) in norm_paths_to_remove:
                        removed_items.append(val)
                        if list_key == "white_list":
                            self.sync_driver_whitelist(val, False)

                        continue
                new_list.append(item)
            
            self.pyas_config[list_key] = new_list
            
            if len(self.pyas_config[list_key]) < original_len:
                self.write_log("INFO", "Config Update", detail=f"List [{list_key}] remove: {removed_items}")
                self.save_config()
                return True

        return False

    def extract_list_items(self, paths, dest_dir):
        if not dest_dir or not os.path.exists(dest_dir):
            return False

        extracted_count = 0
        for raw_path in paths:
            src = self.norm_path(raw_path, must_exist=True)
            if not src:
                continue

            base_name = os.path.basename(src)
            target_path = os.path.join(dest_dir, base_name)
            
            if os.path.exists(target_path):
                name, ext = os.path.splitext(base_name)
                counter = 1

                while os.path.exists(target_path):
                    target_path = os.path.join(dest_dir, f"{name} ({counter}){ext}")
                    counter += 1
                    
            was_locked = False
            src_norm = os.path.normcase(src)
            src_dir = src_norm + os.sep
            
            with self.lock_file_ops:
                for locked_path in self.virus_lock:
                    locked_norm = os.path.normcase(locked_path)
                    if locked_norm == src_norm or locked_norm.startswith(src_dir):
                        was_locked = True
                        break

                if was_locked:
                    self.lock_file(src, False)
                    
            try:
                if os.path.isdir(src):
                    shutil.copytree(src, target_path)
                else:
                    shutil.copy2(src, target_path)
                extracted_count += 1
                self.write_log("INFO", "File Extract", source=src, target=target_path, operate=True)

            except Exception as e:
                self.write_log("WARN", "extract_list_items", source=src, detail=str(e), success=False)
            finally:
                if was_locked:
                    self.lock_file(src, True)
                    
        return extracted_count > 0

####################################################################################################

    def set_window(self, window):
        self._window = window

    def minimize(self):
        if self._window:
            self._window.minimize()
        else:
            hwnd = self.user32.FindWindowW(None, "PYAS Security")
            if hwnd:
                self.user32.ShowWindow(hwnd, 6)

    def hide_window(self):
        if self._window:
            self._window.hide()

    def get_app_icon(self):
        icon_path = os.path.join(self.path_pyas, "Interface", "static", "img", "icon.ico")
        if os.path.exists(icon_path):
            try:
                return Image.open(icon_path)
            except Exception:
                pass

    def get_tray_text(self, key):
        texts = {
            "open_ui": {
                "traditional_switch": "開啟介面", "simplified_switch": "打开界面", "english_switch": "Open PYAS",
                "japanese_switch": "PYAS を開く", "korean_switch": "PYAS 열기", "french_switch": "Ouvrir PYAS",
                "spanish_switch": "Abrir PYAS", "hindi_switch": "PYAS खोलें", "arabic_switch": "فتح PYAS",
                "russian_switch": "Открыть PYAS", "slovenian_switch": "Odpri PYAS"
            },
            "optimize_mem": {
                "traditional_switch": "一鍵加速", "simplified_switch": "一键加速", "english_switch": "Memory Boost",
                "japanese_switch": "メモリ最適化", "korean_switch": "메모리 최적화", "french_switch": "Optimiser",
                "spanish_switch": "Optimizar", "hindi_switch": "मेमोरी बूस्ट", "arabic_switch": "تسريع",
                "russian_switch": "Ускорение", "slovenian_switch": "Optimizacija"
            },
            "check_update": {
                "traditional_switch": "檢查更新", "simplified_switch": "检查更新", "english_switch": "Check Update",
                "japanese_switch": "更新を確認", "korean_switch": "업데이트 확인", "french_switch": "Vérifier la mise à jour",
                "spanish_switch": "Buscar actualizaciones", "hindi_switch": "अद्यतन जाँचे", "arabic_switch": "التحقق من التحديثات",
                "russian_switch": "Проверить обновления", "slovenian_switch": "Preveri posodobitve"
            },
            "exit_app": {
                "traditional_switch": "退出防護", "simplified_switch": "退出防护", "english_switch": "Exit Security",
                "japanese_switch": "保護を終了", "korean_switch": "보호 종료", "french_switch": "Quitter la sécurité",
                "spanish_switch": "Salir de la seguridad", "hindi_switch": "सुरक्षा से बाहर निकलें", "arabic_switch": "خروج من الحماية",
                "russian_switch": "Выйти из защиты", "slovenian_switch": "Izhod iz zaščite"
            }
        }
        return self._loc(texts.get(key, {}))

    def show_tray(self):
        if self.tray_icon is not None:
            return

        menu = pystray.Menu(
            pystray.MenuItem(lambda item: self.get_tray_text("open_ui"), self.restore_from_tray, default=True),
            pystray.MenuItem(lambda item: self.get_tray_text("optimize_mem"), self.optimize_memory),
            pystray.MenuItem(lambda item: self.get_tray_text("check_update"), self.tray_check_update),
            pystray.MenuItem(lambda item: self.get_tray_text("exit_app"), self.close)
        )
        self.tray_icon = pystray.Icon("PYAS", self.get_app_icon(), "PYAS Security", menu)
        self.tray_icon.run_detached()

    def tray_check_update(self, icon=None, item=None):
        def _check():
            res = self.check_update()
            
            title_error = self._loc({
                "traditional_switch": "錯誤", "simplified_switch": "错误", "english_switch": "Error",
                "japanese_switch": "エラー", "korean_switch": "오류", "french_switch": "Erreur",
                "spanish_switch": "Error", "hindi_switch": "त्रुटि", "arabic_switch": "خطأ",
                "russian_switch": "Ошибка", "slovenian_switch": "Napaka"})

            title_prompt = self._loc({
                "traditional_switch": "提示", "simplified_switch": "提示", "english_switch": "Prompt",
                "japanese_switch": "プロンプト", "korean_switch": "프롬프트", "french_switch": "Indication",
                "spanish_switch": "Aviso", "hindi_switch": "सुझाव", "arabic_switch": "تلميح",
                "russian_switch": "Подсказка", "slovenian_switch": "Namig"})

            msg_fail = self._loc({
                "traditional_switch": "檢查更新失敗", "simplified_switch": "检查更新失败", "english_switch": "Update check failed",
                "japanese_switch": "アップデートの確認に失敗しました", "korean_switch": "업데이트 확인 실패", "french_switch": "Échec de la vérification des mises à jour",
                "spanish_switch": "Fallo al buscar actualizaciones", "hindi_switch": "अपडेट की जाँच विफल रही", "arabic_switch": "فشل التحقق من التحديثات",
                "russian_switch": "Ошибка проверки обновлений", "slovenian_switch": "Preverjanje posodobitev ni uspelo"})

            msg_new = self._loc({
                "traditional_switch": "發現新版本", "simplified_switch": "发现新版本", "english_switch": "New version found",
                "japanese_switch": "新しいバージョンが見つかりました", "korean_switch": "새 버전을 찾았습니다", "french_switch": "Nouvelle version trouvée",
                "spanish_switch": "Nueva versión encontrada", "hindi_switch": "नया संस्करण मिला", "arabic_switch": "تم العثور على إصدار جديد",
                "russian_switch": "Найдена новая версия", "slovenian_switch": "Najdena nova različica"})

            msg_latest = self._loc({
                "traditional_switch": "當前已是最新版本", "simplified_switch": "当前已是最新版本", "english_switch": "Currently at latest version",
                "japanese_switch": "現在は最新バージョンです", "korean_switch": "현재 최신 버전입니다", "french_switch": "Actuellement à la dernière version",
                "spanish_switch": "Actualmente en la última versión", "hindi_switch": "वर्तमान में नवीनतम संस्करण है", "arabic_switch": "أنت تستخدم أحدث إصدار حاليًا",
                "russian_switch": "Установлена последняя версия", "slovenian_switch": "Trenutno imate najnovejšo različico"})

            if res.get("error"):
                self.show_alert(title_error, msg_fail, "error")

            elif res.get("has_update"):
                msg = f"{msg_new} {res.get('latest')}\n({res.get('current')} -> {res.get('latest')})"
                if self.show_confirm(title_prompt, msg):
                    self.open_url(res.get("url"))

            else:
                msg = f"{msg_latest} {res.get('current')}"
                self.show_alert(title_prompt, msg, "info")
                
        threading.Thread(target=_check, daemon=True).start()

    def restore_from_tray(self, icon=None, item=None):
        if self._window:
            self._window.restore()
            self._window.show()

            hwnd = self.user32.FindWindowW(None, "PYAS Security")
            if hwnd:
                self.user32.SetForegroundWindow(hwnd)

    def close(self, *args, **kwargs):
        if self.tray_icon:
            try:
                self.tray_icon.stop()
            except Exception:
                pass
            self.tray_icon = None

        if self._window:
            try:
                self._window.hide()
            except Exception:
                pass

        with self.lock_config:
            self.pyas_config["process_switch"] = False
            self.pyas_config["document_switch"] = False
            self.pyas_config["system_switch"] = False
            self.pyas_config["driver_switch"] = False
            self.pyas_config["network_switch"] = False

        self.stop_system_driver()
        
        with self.lock_file_ops:
            if getattr(self, 'h_dir_file', None):
                try:
                    self.kernel32.CloseHandle(self.h_dir_file)
                except Exception:
                    pass
                self.h_dir_file = None
                
            if hasattr(self, 'virus_lock'):
                for file_path, (fd, lock_size) in list(self.virus_lock.items()):
                    try:
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, lock_size)
                    except Exception:
                        pass
                    try:
                        os.close(fd)
                    except Exception:
                        pass
                self.virus_lock.clear()
        
        with self.lock_proc:
            if hasattr(self, 'suspended_procs'):
                for h in list(self.suspended_procs):
                    try:
                        self.ntdll.NtResumeProcess(h)
                        self.kernel32.CloseHandle(h)
                    except Exception:
                        pass
                self.suspended_procs.clear()

        if hasattr(self, 'h_mutex') and self.h_mutex:
            try:
                self.kernel32.CloseHandle(self.h_mutex)
            except Exception:
                pass

        if self._window:
            self._window.destroy()

        with self.lock_logs:
            if getattr(self, 'logs_dirty', False):
                try:
                    os.makedirs(os.path.dirname(self.file_log), exist_ok=True)
                    with open(self.file_log, "w", encoding="utf-8") as f:
                        json.dump(self.logs_data, f, indent=4, ensure_ascii=False)
                except Exception:
                    pass

        with self.lock_config:
            pass

        os._exit(0)

    def init_ui_ready(self):
        with self.lock_config:
            if self.engine_initialized:
                return

            self.engine_initialized = True
        self.start_daemon_thread(self.init_engine_thread)

    def show_notification(self, title, message):
        try:
            if self.tray_icon:
                self.tray_icon.notify(message, title)

        except Exception as e:
            self.write_log("WARN", "show_notification", detail=str(e), success=False)

    def trigger_block_notification(self, action, source, target, code):
        if action not in ["Process Block", "Process DLL Block", "File Block", "Network Block", "Driver Block"]:
            return

        titles = {
            "Process Block": {
                "traditional_switch": "進程防護", "simplified_switch": "进程防护", "english_switch": "Process Protection",
                "japanese_switch": "プロセス保護", "korean_switch": "프로세스 보호", "french_switch": "Protection des Processus",
                "spanish_switch": "Protección de Procesos", "hindi_switch": "प्रक्रिया सुरक्षा", "arabic_switch": "حماية العمليات",
                "russian_switch": "Защита процессов", "slovenian_switch": "Zaščita procesov"
            },
            "Process DLL Block": {
                "traditional_switch": "記憶體防護", "simplified_switch": "内存防护", "english_switch": "Memory Protection",
                "japanese_switch": "メモリ保護", "korean_switch": "메모리 보호", "french_switch": "Protection de la mémoire",
                "spanish_switch": "Protección de memoria", "hindi_switch": "मेमोरी सुरक्षा", "arabic_switch": "حماية الذاكرة",
                "russian_switch": "Защита памяти", "slovenian_switch": "Zaščita pomnilnika"
            },
            "File Block": {
                "traditional_switch": "檔案防護", "simplified_switch": "文件防护", "english_switch": "File Protection",
                "japanese_switch": "ファイル保護", "korean_switch": "파일 보호", "french_switch": "Protection des Fichiers",
                "spanish_switch": "Protección de Archivos", "hindi_switch": "फ़ाइल सुरक्षा", "arabic_switch": "حماية الملفات",
                "russian_switch": "Защита файлов", "slovenian_switch": "Zaščita datotek"
            },
            "Network Block": {
                "traditional_switch": "網路防護", "simplified_switch": "网络防护", "english_switch": "Network Protection",
                "japanese_switch": "ネットワーク保護", "korean_switch": "네트워크 보호", "french_switch": "Protection Réseau",
                "spanish_switch": "Protección de Red", "hindi_switch": "नेटवर्क सुरक्षा", "arabic_switch": "حماية الشبكة",
                "russian_switch": "Сетевая защита", "slovenian_switch": "Omrežna zaščita"
            },
            "Driver Block": {
                "traditional_switch": "驅動防護", "simplified_switch": "驱动防护", "english_switch": "Driver Protection",
                "japanese_switch": "ドライバー保護", "korean_switch": "드라이버 보호", "french_switch": "Protection des Pilotes",
                "spanish_switch": "Protección de Controladores", "hindi_switch": "ड्राइवर सुरक्षा", "arabic_switch": "حماية برامج التشغيل",
                "russian_switch": "Защита драйверов", "slovenian_switch": "Zaščita gonilnikov"
            }
        }

        path = source or ""
        messages = {
            "traditional_switch": f"威脅已終止: {path}", "simplified_switch": f"威胁已终止: {path}", "english_switch": f"Threat terminated: {path}",
            "japanese_switch": f"脅威が終了しました: {path}", "korean_switch": f"위협이 종료되었습니다: {path}", "french_switch": f"Menace terminée : {path}",
            "spanish_switch": f"Amenaza terminada: {path}", "hindi_switch": f"खतरा समाप्त: {path}", "arabic_switch": f"تم إنهاء التهديد: {path}",
            "russian_switch": f"Угроза устранена: {path}", "slovenian_switch": f"Grožnja odpravljena: {path}"
        }

        title = self._loc(titles.get(action, {}))
        message = self._loc(messages)

        try:
            self.tray_icon.notify(message, title)
        except Exception:
            pass

    def show_alert(self, title, message, style="info"):
        flags = 0x00000000 | (0x00000010 if style == "error" else 0x00000030 if style == "warning" else 0x00000040)
        self.user32.MessageBoxW(0, message, title, flags)
        return True

    def show_confirm(self, title, message):
        return self.user32.MessageBoxW(0, message, title, 0x00000004 | 0x00000020) == 6

    def register_context_menu(self, enable):
        paths = [r"Software\Classes\*\shell\PYAS_Scan", r"Software\Classes\Directory\shell\PYAS_Scan"]
        cmd_path = f'"{self.file_pyas}"' if getattr(sys, 'frozen', False) else f'"{self.python}" "{self.file_pyas}"'

        try:
            for path in paths:
                if enable:
                    self._reg_write(winreg.HKEY_CURRENT_USER, path, None, winreg.REG_SZ, "PYAS Security Scan")
                    self._reg_write(winreg.HKEY_CURRENT_USER, path, "Icon", winreg.REG_SZ, f'{cmd_path},0')
                    self._reg_write(winreg.HKEY_CURRENT_USER, rf"{path}\command", None, winreg.REG_SZ, f'{cmd_path} -scan "%1"')
                else:
                    self._reg_delete(winreg.HKEY_CURRENT_USER, rf"{path}\command")
                    self._reg_delete(winreg.HKEY_CURRENT_USER, path)

        except Exception as e:
            self.write_log("WARN", "register_context_menu", detail=str(e), success=False)

    def trigger_context_scan(self, target):
        if self._window:
            self._window.evaluate_js(f"if(window.triggerContextScan) window.triggerContextScan({json.dumps(target.replace(os.sep, '/'))});")

    def on_drop(self, e):
        def _process_drop():
            try:
                files = e.get('dataTransfer', {}).get('files', [])
                paths = [f.get('pywebviewFullPath') for f in files if f.get('pywebviewFullPath')]
                if paths and self._window:
                    self._window.evaluate_js(f"if(window.triggerContextScan) window.triggerContextScan({json.dumps(paths)});")

            except Exception as ex:
                self.write_log("WARN", "on_drop", detail=str(ex), success=False)

        threading.Thread(target=_process_drop, daemon=True).start()

    def select_files(self):
        if self._window: 
            return self._window.create_file_dialog(getattr(webview, 'OPEN_DIALOG', 10), allow_multiple=True) or []
        return []

    def select_folder(self):
        if self._window: 
            return self._window.create_file_dialog(getattr(webview, 'FOLDER_DIALOG', 20)) or []
        return []

    def open_file_location(self, file_path):
        if not file_path:
            return False

        expanded_path = os.path.expandvars(file_path).strip('"').strip("'")
        reg_prefixes = ("HKLM", "HKCU", "HKCR", "HKU", "HKCC", "HKEY_")

        if expanded_path.upper().startswith(reg_prefixes):
            try:
                full_path = expanded_path
                if full_path.startswith("HKLM"):
                    full_path = full_path.replace("HKLM", "HKEY_LOCAL_MACHINE", 1)
                elif full_path.startswith("HKCU"):
                    full_path = full_path.replace("HKCU", "HKEY_CURRENT_USER", 1)
                elif full_path.startswith("HKCR"):
                    full_path = full_path.replace("HKCR", "HKEY_CLASSES_ROOT", 1)
                elif full_path.startswith("HKU"):
                    full_path = full_path.replace("HKU", "HKEY_USERS", 1)
                elif full_path.startswith("HKCC"):
                    full_path = full_path.replace("HKCC", "HKEY_CURRENT_CONFIG", 1)

                subprocess.run(["taskkill", "/F", "/IM", "regedit.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000)
                self._reg_write(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit", "LastKey", winreg.REG_SZ, full_path)
                subprocess.Popen("regedit.exe")

                return True
            except Exception:
                pass
            return False

        if os.path.exists(expanded_path):
            try:
                clean_path = os.path.normpath(expanded_path)
                subprocess.Popen(f'explorer /select,"{clean_path}"')
                return True

            except Exception:
                pass
        return False

    def open_website(self):
        try:
            return webbrowser.open(self.pyas_config.get("api_host"))
        except Exception:
            return False

    def open_url(self, url):
        try:
            return webbrowser.open(url)
        except Exception:
            return False

####################################################################################################

    def start_daemon_thread(self, target, *args, **kwargs):
        t = threading.Thread(target=target, args=args, kwargs=kwargs, daemon=True)
        t.start()
        return t

    def norm_path(self, path, must_exist=True):
        if isinstance(path, list):
            return [p for p in (self.norm_path(x, must_exist) for x in path) if p]

        if isinstance(path, str):
            try:
                ap = os.path.normpath(os.path.abspath(path))
                return ap if (not must_exist or os.path.exists(ap)) else None

            except Exception:
                return None

        return path

    def path_equal(self, a, b):
        pa, pb = self.norm_path(a, must_exist=False), self.norm_path(b, must_exist=False)
        return os.path.normcase(pa) == os.path.normcase(pb) if pa and pb else False

    def get_file_version(self, file_path):
        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

            if hasattr(pe, 'FileInfo'):
                for fl in pe.FileInfo:
                    for info in fl:
                        if getattr(info, 'name', '') in ('StringFileInfo', b'StringFileInfo'):

                            for st in getattr(info, 'StringTable', []):
                                for k, val in st.entries.items():
                                    k_str = k.decode('utf-8', 'ignore') if isinstance(k, bytes) else str(k)
                                    v_str = val.decode('utf-8', 'ignore') if isinstance(val, bytes) else str(val)
                                    if k_str == 'FileVersion':
                                        pe.close()
                                        return v_str.strip()

            pe.close()
        except Exception:
            pass

        return "0.0.0.0"

    def compare_versions(self, v1, v2):
        try:
            val1 = tuple(int(x) for x in re.findall(r"\d+", re.sub(r"^[vV]\s*", "", str(v1))))
            val2 = tuple(int(x) for x in re.findall(r"\d+", re.sub(r"^[vV]\s*", "", str(v2))))
            return val1 >= val2

        except Exception:
            return False

    def check_update(self):
        try:
            current = self.pyas_config.get("version", "0.0.0")
            j = requests.get("https://api.github.com/repos/87owo/PYAS/releases/latest", headers={"Accept": "application/vnd.github+json", "User-Agent": "PYAS"}, timeout=10).json()
            latest = str(j.get("tag_name") or j.get("name") or "").strip()
            page = j.get("html_url") or "https://github.com/87owo/PYAS/releases"

            if latest:
                if not self.compare_versions(current, latest) and current != latest:
                    return {"has_update": True, "latest": latest, "current": current, "url": page}
                return {"has_update": False, "latest": latest, "current": current, "url": page}

        except Exception:
            pass
        return {"error": True}

    def calc_file_hash(self, file_path, block_size=65536):
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(block_size), b""): h.update(chunk)

            return h.hexdigest()
        except Exception:
            return None

    def device_path_to_drive(self, path):
        if not path:
            return ""

        for d in range(65, 91):
            drive = f"{chr(d)}:"
            buf = ctypes.create_unicode_buffer(1024)

            if self.kernel32.QueryDosDeviceW(drive, buf, 1024) and path.startswith(buf.value):
                return path.replace(buf.value, drive, 1)

        return path

    def get_exe_info(self, pid):
        name, file_path = None, None
        h = self.kernel32.OpenProcess(0x1000, False, pid)
        if h:
            try:
                buf = ctypes.create_unicode_buffer(1024)
                size = ctypes.wintypes.DWORD(1024)

                if self.kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                    file_path = self.norm_path(buf.value)
                    if file_path:
                        name = os.path.basename(file_path)

                elif self.psapi.GetProcessImageFileNameW(h, buf, 1024):
                    file_path = self.norm_path(self.device_path_to_drive(buf.value))
                    if file_path:
                        name = os.path.basename(file_path)

            finally:
                self.kernel32.CloseHandle(h)

        return name, file_path

    def get_process_file(self, h_process):
        buf = ctypes.create_unicode_buffer(1024)
        if self.psapi.GetProcessImageFileNameW(h_process, buf, 1024):
            return self.norm_path(self.device_path_to_drive(buf.value))

        return ""

    def get_process_cmdline(self, h):
        pbi = PROCESS_BASIC_INFORMATION()
        retlen = ctypes.wintypes.ULONG(0)
        if self.ntdll.NtQueryInformationProcess(h, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(retlen)) != 0:
            return ""

        pointer_size = ctypes.sizeof(ctypes.c_void_p)
        addr_pp = (int(pbi.PebBaseAddress) if pbi.PebBaseAddress else 0) + (0x20 if pointer_size == 8 else 0x10)
        if not addr_pp:
            return ""

        read_buf = (ctypes.c_ubyte * pointer_size)()
        lpBytesRead = ctypes.c_size_t(0)
        if not self.kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr_pp), read_buf, pointer_size, ctypes.byref(lpBytesRead)):
            return ""

        proc_params_address = ctypes.c_void_p.from_buffer_copy(read_buf).value
        if not proc_params_address:
            return ""

        us = UNICODE_STRING()
        if not self.kernel32.ReadProcessMemory(h, ctypes.c_void_p(int(proc_params_address) + (0x70 if pointer_size == 8 else 0x40)), ctypes.byref(us), ctypes.sizeof(us), ctypes.byref(lpBytesRead)):
            return ""
        if not us.Buffer or us.Length == 0:
            return ""

        buf = (ctypes.c_wchar * int(us.Length // 2))()
        if not self.kernel32.ReadProcessMemory(h, ctypes.c_void_p(int(us.Buffer)), buf, us.Length, ctypes.byref(lpBytesRead)):
            return ""

        return "".join(buf)

    def extract_paths_from_cmdline(self, cmdline):
        if not cmdline:
            return []

        found = []
        for m in re.finditer(r'"([^"]+)"|\'([^\']+)\'', cmdline):
            path = m.group(1) or m.group(2)
            if re.match(r'^[A-Za-z]:\\|^\\\\', path):
                found.append(path)

        if not found:
            m = re.search(r'([A-Za-z]:\\[^\*?"<>\|]+\.(?:exe|dll|bat|cmd|vbs|sys|com|pif))', cmdline, re.IGNORECASE)
            if m:
                found.append(m.group(1))

        if not found:
            argc = ctypes.c_int(0)
            argv = self.shell32.CommandLineToArgvW(cmdline, ctypes.byref(argc))
            if argv:
                args = [argv[i] for i in range(argc.value)]
                self.kernel32.LocalFree(ctypes.cast(argv, ctypes.c_void_p))
                patterns = [r'([A-Za-z]:\\[^"\']+)', r'(\\\\[^"\']+)', r'(\.\\[^"\']+)', r'(\./[^"\']+)', r'([A-Za-z]:/[^"\']+)', r'([^\s]*\\[^\s]+)']

                for arg in args:
                    for p in patterns:
                        for match in re.finditer(p, arg): found.append(match.group(1).strip('"').strip("'"))

        return list(dict.fromkeys([p.strip('"').strip("'") for p in found]))

    def _enum_processes(self):
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        snapshot = self.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        
        if snapshot in (-1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            return

        try:
            if self.kernel32.Process32FirstW(snapshot, ctypes.byref(pe)):
                while True:
                    yield pe.th32ProcessID, pe.szExeFile
                    if not self.kernel32.Process32NextW(snapshot, ctypes.byref(pe)):
                        break
        finally:
            self.kernel32.CloseHandle(snapshot)

    def get_process_list(self):
        result = []
        for pid, exe_name in self._enum_processes():
            name, file_path = None, None
            if pid > 4:
                name, file_path = self.get_exe_info(pid)
            
            if not name:
                try:
                    name = exe_name
                except Exception:
                    name = "Unknown"
                    
            result.append({"pid": pid, "name": name, "path": file_path or "None"})
            
        return result

    def get_process_list_pids(self):
        return {pid for pid, _ in self._enum_processes()}

    def kill_process(self, pid):
        try:
            h = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if h:
                try:
                    file_path = self.norm_path(self.get_process_file(h))
                    if self.path_equal(file_path, self.file_pyas):
                        return False

                    self.kernel32.TerminateProcess(h, 0)
                    return True
                finally:
                    self.kernel32.CloseHandle(h)

        except Exception as e:
            self.write_log("WARN", "kill_process", pid=pid, detail=str(e), operate=True, success=False)
        return False

    def get_connections_list(self):
        connections = set()
        try:
            size = ctypes.wintypes.DWORD()
            if self.iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), True, 2, 5, 0) != 122:
                return connections

            buf = ctypes.create_string_buffer(size.value)
            if self.iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), True, 2, 5, 0) != 0:
                return connections

            num_entries = ctypes.cast(buf, ctypes.POINTER(ctypes.wintypes.DWORD)).contents.value
            for i in range(num_entries):
                row = MIB_TCPROW_OWNER_PID.from_address(ctypes.addressof(buf) + ctypes.sizeof(ctypes.wintypes.DWORD) + i * ctypes.sizeof(MIB_TCPROW_OWNER_PID))
                connections.add((row.dwOwningPid, row.dwRemoteAddr, row.dwRemotePort))

        except Exception:
            pass
        return connections

    def get_traffic_list(self):
        conns = self.get_connections_list()
        conn_map = {}
        for pid, _, _ in conns:
            conn_map[pid] = conn_map.get(pid, 0) + 1

        current_io = {}
        current_time = time.time()
        
        with self.lock_io:
            time_diff = current_time - self.last_io_time
            if time_diff <= 0:
                time_diff = 1

            self.last_io_time = current_time
            old_counters = self.last_io_counters.copy()

        result = []
        exist_process = self.get_process_list_pids()
        
        for pid in exist_process:
            name, file_path = "Unknown", ""
            if pid > 4:
                name, file_path = self.get_exe_info(pid)
            else:
                name = "System"
            
            down_speed, up_speed = 0, 0
            h = self.kernel32.OpenProcess(0x1000, False, pid)
            if h:
                try:
                    io = IO_COUNTERS()
                    if self.kernel32.GetProcessIoCounters(h, ctypes.byref(io)):
                        current_io[pid] = (io.ReadTransferCount, io.WriteTransferCount)

                        if pid in old_counters:
                            old_read, old_write = old_counters[pid]
                            down_speed = max(0, (io.ReadTransferCount - old_read) / time_diff)
                            up_speed = max(0, (io.WriteTransferCount - old_write) / time_diff)

                finally:
                    self.kernel32.CloseHandle(h)
            
            count = conn_map.get(pid, 0)
            if count > 0 or down_speed > 0 or up_speed > 0:
                result.append({"pid": pid, "name": name, "path": file_path or "None", "down": int(down_speed), "up": int(up_speed), "conn": count})

        with self.lock_io:
            self.last_io_counters = current_io
        return result
    
    def _traverse_delete(self, path):
        deleted = 0
        if not path or not os.path.exists(path):
            return deleted

        try:
            items = os.listdir(path)
        except Exception:
            return deleted

        for fd in items:
            file = os.path.join(path, fd)
            try:
                if os.path.isdir(file):
                    if self._is_reparse_point(file):
                        continue
                        
                    deleted += self._traverse_delete(file)
                    try:
                        os.rmdir(file)
                    except Exception:
                        pass

                else:
                    if file.lower().endswith(('.sys', '.dll', '.exe', '.ini', '.dat')):
                        continue

                    size = os.path.getsize(file)
                    os.remove(file)
                    deleted += size

            except Exception:
                continue

        return deleted

    def _get_junk_dirs(self):
        return [
            self.path_temp, 
            self.path_systemp, 
            os.path.join(self.path_system, "SoftwareDistribution", "Download")
        ]

    def _yield_log_files(self):
        log_dir = os.path.join(self.path_system, "Logs")
        if os.path.exists(log_dir):
            for root, _, files in os.walk(log_dir):
                for file in files:
                    if file.lower().endswith(('.log', '.etl', '.evtx')):
                        yield os.path.join(root, file)

    def _get_recycle_bin_size(self):
        try:
            info = SHQUERYRBINFO()
            info.cbSize = ctypes.sizeof(SHQUERYRBINFO)
            
            if self.shell32.SHQueryRecycleBinW(None, ctypes.byref(info)) == 0 and info.i64Size > 0:
                return info.i64Size
        except Exception:
            pass
            
        return 0
    
    def scan_system_junk(self):
        junk_list = []
        try:
            for path in self._get_junk_dirs():
                if os.path.exists(path):
                    for root, _, files in os.walk(path):
                        for file in files:
                            if not file.lower().endswith(('.sys', '.dll', '.exe', '.ini', '.dat')):
                                try:
                                    fp = os.path.join(root, file)
                                    junk_list.append({"path": fp, "size": os.path.getsize(fp)})
                                except Exception:
                                    pass

            for fp in self._yield_log_files():
                try:
                    junk_list.append({"path": fp, "size": os.path.getsize(fp)})
                except Exception:
                    pass

            rb_size = self._get_recycle_bin_size()
            if rb_size > 0:
                junk_list.append({"path": "Recycle Bin", "size": rb_size})

            return junk_list

        except Exception as e:
            self.write_log("WARN", "scan_system_junk", detail=str(e), success=False)
            return []

    def clean_system_junk(self, paths_to_delete=None):
        total_deleted = 0
        try:
            if paths_to_delete is not None:
                for path in paths_to_delete:
                    if path == "Recycle Bin":
                        rb_size = self._get_recycle_bin_size()
                        if rb_size > 0 and self.shell32.SHEmptyRecycleBinW(None, None, 7) == 0:
                            total_deleted += rb_size
                        continue

                    if path.lower().endswith(('.sys', '.dll', '.exe', '.ini', '.dat')):
                        continue

                    try:
                        size = os.path.getsize(path)
                        os.remove(path)
                        total_deleted += size
                    except Exception:
                        pass
            else:
                for path in self._get_junk_dirs():
                    total_deleted += self._traverse_delete(path)

                for fp in self._yield_log_files():
                    try:
                        size = os.path.getsize(fp)
                        os.remove(fp)
                        total_deleted += size
                    except Exception:
                        pass

                rb_size = self._get_recycle_bin_size()
                if rb_size > 0 and self.shell32.SHEmptyRecycleBinW(None, None, 7) == 0:
                    total_deleted += rb_size

                try:
                    for log_type in ["Application", "Security", "Setup", "System"]:
                        log_path = os.path.join(self.path_system, "System32", "winevt", "Logs", f"{log_type}.evtx")
                        size = os.path.getsize(log_path) if os.path.exists(log_path) else 0
                        if subprocess.run(["wevtutil", "cl", log_type], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000).returncode == 0:
                            total_deleted += size
                except Exception:
                    pass

            self.write_log("INFO", "Clean Junk", detail=f"Deleted {total_deleted // 1024} KB", operate=True)
            return total_deleted

        except Exception as e:
            self.write_log("WARN", "clean_system_junk", detail=str(e), operate=True, success=False)
            return 0

    def optimize_memory(self, icon=None, item=None):
        def _optimize():
            try:
                hwnd = self.user32.GetForegroundWindow()
                fg_pid = ctypes.wintypes.DWORD(0)
                if hwnd:
                    self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(fg_pid))

                pids = self.get_process_list_pids()
                optimized_count = 0
                
                skip_set = {
                    "dwm.exe", "explorer.exe", "csrss.exe", "smss.exe", "winlogon.exe",
                    "lsass.exe", "services.exe", "svchost.exe", "wininit.exe", "audiodg.exe",
                    "spoolsv.exe", "sihost.exe", "fontdrvhost.exe", "taskmgr.exe"
                }

                for pid in pids:
                    if pid <= 4 or pid == self.pid_pyas or pid == fg_pid.value:
                        continue
                        
                    name, _ = self.get_exe_info(pid)
                    if name and name.lower() in skip_set:
                        continue

                    h = self.kernel32.OpenProcess(0x0100, False, pid)
                    if h:
                        try:
                            if self.kernel32.SetProcessWorkingSetSize(h, ctypes.c_size_t(-1), ctypes.c_size_t(-1)):
                                optimized_count += 1
                        finally:
                            self.kernel32.CloseHandle(h)

                title = self._loc({
                    "traditional_switch": "一鍵加速", "simplified_switch": "一键加速", "english_switch": "Memory Boost",
                    "japanese_switch": "メモリ最適化", "korean_switch": "메모리 최적화", "french_switch": "Optimiser",
                    "spanish_switch": "Optimizar", "hindi_switch": "मेमोरी बूस्ट", "arabic_switch": "تسريع",
                    "russian_switch": "Ускорение", "slovenian_switch": "Optimizacija"
                })
                
                msg = self._loc({
                    "traditional_switch": f"已釋放 {optimized_count} 個背景進程的記憶體",
                    "simplified_switch": f"已释放 {optimized_count} 个后台进程的内存",
                    "english_switch": f"Freed memory for {optimized_count} background processes",
                    "japanese_switch": f"{optimized_count} 個のバックグラウンドプロセスのメモリを解放しました",
                    "korean_switch": f"{optimized_count}개 백그라운드 프로세스 메모리 확보",
                    "french_switch": f"Mémoire libérée pour {optimized_count} processus",
                    "spanish_switch": f"Memoria liberada para {optimized_count} procesos",
                    "hindi_switch": f"{optimized_count} पृष्ठभूमि प्रक्रियाओं के लिए मेमोरी मुक्त की गई",
                    "arabic_switch": f"تم تحرير الذاكرة لـ {optimized_count} من العمليات في الخلفية",
                    "russian_switch": f"Освобождена память {optimized_count} фоновых процессов",
                    "slovenian_switch": f"Sproščen pomnilnik za {optimized_count} procesov v ozadju"
                })

                self.show_notification(title, msg)
                self.write_log("INFO", "Memory Boost", detail=f"Optimized {optimized_count} processes", operate=True)

            except Exception as e:
                self.write_log("WARN", "optimize_memory", detail=str(e), success=False)

        threading.Thread(target=_optimize, daemon=True).start()

    def get_startup_list(self):
        items = []

        def get_reg_startup():
            res = []
            paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "enabled"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "enabled"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run_Disabled", "disabled"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run_Disabled", "disabled")
            ]

            for root, path, status in paths:
                try:
                    with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as reg:
                        i = 0
                        while True:
                            try:
                                name, val, _ = winreg.EnumValue(reg, i)
                                file_path = self.extract_paths_from_cmdline(val)
                                fp = file_path[0] if file_path else val
                                res.append({"id": f"reg|{root}|{path}|{name}", "type": "type_reg", "name": name, "status": status, "path": fp})
                                i += 1

                            except OSError:
                                break
                except Exception:
                    pass
            return res

        def get_services():
            res = []
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services", 0, winreg.KEY_READ) as reg:
                    i = 0
                    while True:
                        try:
                            name = winreg.EnumKey(reg, i)
                            i += 1
                            try:
                                with winreg.OpenKey(reg, name, 0, winreg.KEY_READ) as sub:
                                    stype, _ = winreg.QueryValueEx(sub, "Type")
                                    if stype not in (16, 32, 256):
                                        continue

                                    start, _ = winreg.QueryValueEx(sub, "Start")
                                    if start not in (2, 3, 4):
                                        continue

                                    path, _ = winreg.QueryValueEx(sub, "ImagePath")
                                    if path and "svchost" not in path.lower() and "windows" not in path.lower():
                                        fp = self.extract_paths_from_cmdline(path)
                                        fpp = fp[0] if fp else path
                                        status = "enabled" if start == 2 else "disabled"
                                        res.append({"id": f"srv|{name}", "type": "type_srv", "name": name, "status": status, "path": fpp})

                            except Exception:
                                pass
                        except OSError:
                            break

            except Exception:
                pass
            return res

        def get_tasks():
            res = []
            try:
                proc = subprocess.run(["schtasks", "/query", "/fo", "csv", "/v"], capture_output=True, text=True, creationflags=0x08000000)
                reader = csv.reader(io.StringIO(proc.stdout))
                next(reader, None)

                for row in reader:
                    if len(row) > 8 and row[1].strip() and row[8].strip() and row[8] != "N/A":
                        name = row[1].split('\\')[-1]
                        path = row[8]
                        status = row[3]

                        if path and "windows" not in path.lower():
                            fp = self.extract_paths_from_cmdline(path)
                            fpp = fp[0] if fp else path
                            res.append({"id": f"tsk|{row[1]}", "type": "type_tsk", "name": name, "status": "disabled" if status == "Disabled" else "enabled", "path": fpp})

            except Exception:
                pass
            return res

        with ThreadPoolExecutor(max_workers=3) as executor:
            f1 = executor.submit(get_reg_startup)
            f2 = executor.submit(get_services)
            f3 = executor.submit(get_tasks)

            items.extend(f1.result())
            items.extend(f2.result())
            items.extend(f3.result())

        return items

    def manage_startup(self, items, action):
        def process_item(item_id):
            try:
                parts = item_id.split('|')
                stype = parts[0]

                if stype == "reg":
                    root, old_path, name = int(parts[1]), parts[2], parts[3]
                    if action == "delete":
                        self._reg_delete(root, old_path, name)

                    else:
                        new_path = old_path.replace("_Disabled", "") if action == "enable" else (old_path if "_Disabled" in old_path else old_path + "_Disabled")
                        if old_path != new_path:
                            val = self._reg_read(root, old_path, name)
                            if val:
                                self._reg_write(root, new_path, name, winreg.REG_SZ, val)
                                self._reg_delete(root, old_path, name)

                elif stype == "srv":
                    name = parts[1]
                    if action == "delete":
                        subprocess.run(["sc", "delete", name], capture_output=True, creationflags=0x08000000)

                    else:
                        mode = "auto" if action == "enable" else "disabled"
                        subprocess.run(["sc", "config", name, f"start=", mode], capture_output=True, creationflags=0x08000000)

                elif stype == "tsk":
                    name = parts[1]
                    if action == "delete":
                        subprocess.run(["schtasks", "/delete", "/tn", name, "/f"], capture_output=True, creationflags=0x08000000)

                    else:
                        cmd = "/enable" if action == "enable" else "/disable"
                        subprocess.run(["schtasks", "/change", "/tn", name, cmd], capture_output=True, creationflags=0x08000000)

            except Exception as e:
                self.write_log("WARN", "manage_startup", detail=str(e), success=False)
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            list(executor.map(process_item, items))
            
        return True

####################################################################################################

    def init_engine_thread(self):
        try:
            self.start_daemon_thread(self.backup_mbr)
            self.start_daemon_thread(self.relock_file)
            self.start_daemon_thread(self.init_whitelist)
            self.start_daemon_thread(self.popup_intercept_thread)
            
            def log_callback(x):
                self.write_log("INFO", "Load Engine", source=os.path.basename(x))

            self.heuristic.load_path(self.path_heuristic, callback=log_callback)
            self.properties.load_path(self.path_properties, callback=log_callback)
            self.write_log("INFO", "System", detail="Engine Initialization Complete")
            
            if "-scan" in self.args_pyas:
                try:
                    idx = self.args_pyas.index("-scan")
                    self.trigger_context_scan(self.args_pyas[idx+1])
                except Exception:
                    pass
            
            with self.lock_config:
                first_launch = self.pyas_config.get("first_launch", True)
                driver_enabled = self.pyas_config.get("driver_switch", False)
                context_enabled = self.pyas_config.get("context_switch", True)
                autostart_enabled = self.pyas_config.get("autostart_switch", True)

            self.register_context_menu(context_enabled)
            self.manage_autostart(autostart_enabled)
            
            if not first_launch:
                with self.lock_config:
                    if self.pyas_config.get("process_switch"):
                        self.start_daemon_thread(self.protect_proc_thread)
                    if self.pyas_config.get("document_switch"):
                        self.start_daemon_thread(self.protect_file_thread)
                    if self.pyas_config.get("system_switch"):
                        self.start_daemon_thread(self.protect_system_thread)
                    if self.pyas_config.get("network_switch"):
                        self.start_daemon_thread(self.protect_net_thread)

                if driver_enabled:
                    if self.install_system_driver():
                        self.start_daemon_thread(self.pipe_server_thread)
                    else:
                        with self.lock_config:
                            self.pyas_config["driver_switch"] = False
                            self.save_config()

                        self.write_log("WARN", "System", detail="Driver Protection Failed to Start", success=False)

        except Exception as e:
            self.write_log("WARN", "init_engine_thread", detail=str(e), success=False)

    def yield_files(self, targets):
        if isinstance(targets, str):
            if os.path.isdir(targets):
                for root, dirs, files in os.walk(targets):
                    dirs[:] = [d for d in dirs if not self._is_reparse_point(os.path.join(root, d))]
                    for f in files:
                        yield self.norm_path(os.path.join(root, f)), False

            elif os.path.isfile(targets):
                yield self.norm_path(targets), True

        elif isinstance(targets, (list, tuple, set)):
            for t in targets:
                yield from self.yield_files(t)

    def _is_reparse_point(self, path):
        try:
            if os.path.islink(path):
                return True
            if hasattr(os.path, 'isjunction') and os.path.isjunction(path):
                return True
            
            st = os.lstat(path)
            return bool(getattr(st, 'st_file_attributes', 0) & 0x400)
        except OSError:
            return False

    def scan_engine(self, file_path):
        with self.lock_config:
            ext_switch = self.pyas_config.get("extension_switch", False)
            sen_switch = self.pyas_config.get("sensitive_switch", False)
            
        try:
            pe_label, _ = self.properties.pe_scan(file_path, enhanced_mode=sen_switch)
            if pe_label:
                return pe_label
        except Exception:
            pass
            
        try:
            if ext_switch:
                yara_label, _ = self.heuristic.yara_scan(file_path)
                if yara_label:
                    return yara_label
        except Exception:
            pass

        return False

    def safe_scan_engine(self, file_path):
        norm_path = self.norm_path(file_path)
        if not norm_path:
            return False

        file_hash = self.calc_file_hash(norm_path)
        cache_key = file_hash if file_hash else os.path.normcase(norm_path)

        with self.lock_file_ops:
            if cache_key in self.hash_cache:
                return self.hash_cache[cache_key]

            if cache_key in self.scan_events:
                event = self.scan_events[cache_key]
                needs_scan = False
            else:
                event = threading.Event()
                self.scan_events[cache_key] = event
                needs_scan = True

        if not needs_scan:
            event.wait(timeout=60)
            with self.lock_file_ops:
                return self.hash_cache.get(cache_key, False)

        try:
            result = self.scan_engine(norm_path)
            with self.lock_file_ops:
                if len(self.hash_cache) > 10000:
                    for k in list(self.hash_cache.keys())[:1000]:
                        del self.hash_cache[k]

                self.hash_cache[cache_key] = result
            return result

        finally:
            with self.lock_file_ops:
                if cache_key in self.scan_events:
                    self.scan_events[cache_key].set()
                    del self.scan_events[cache_key]

            gc.collect()

    def start_scan(self, targets):
        with self.lock_virus:
            if getattr(self, 'scan_running', False):
                return

            self.scan_running = True
            self.scan_finished = False
            self.virus_results = []
            self.scan_count = 0
            self.scan_start = time.time()

        self.scan_pool.submit(self.scan_worker, targets)

    def scan_worker(self, targets):
        last_update = 0.0
        try:
            for file_path, is_explicit in self.yield_files(targets):
                with self.lock_virus:
                    if not self.scan_running:
                        break
                
                norm_path = self.norm_path(file_path)
                if not norm_path:
                    continue

                current_time = time.time()
                if current_time - last_update >= 0.05:
                    if self._window:
                        js_cmd = f"if(window.updateScanProgress) window.updateScanProgress({json.dumps(norm_path.replace(os.sep, '/'))});"
                        self.ui_queue.put(js_cmd)

                    last_update = current_time

                was_locked = False
                try:
                    with self.lock_file_ops:
                        if norm_path in self.virus_lock:
                            self.lock_file(norm_path, False)
                            was_locked = True

                    if self.is_in_whitelist(norm_path):
                        continue

                    with self.lock_virus:
                        self.scan_count += 1
                    with self.lock_config:
                        ext_filter = self.pyas_config.get("suffix_switch", True)
                        suffix = self.pyas_config.get("suffix", [])
                        
                    if not is_explicit and ext_filter and os.path.splitext(norm_path)[-1].lower() not in suffix:
                        continue

                    result = self.safe_scan_engine(norm_path)
                    if result:
                        with self.lock_virus:
                            self.virus_results.append(norm_path)

                        if self._window: 
                            js_cmd = f"if(window.addVirusResult) window.addVirusResult({json.dumps(result)}, {json.dumps(norm_path.replace(os.sep, '/'))});"
                            self.ui_queue.put(js_cmd)

                        self.write_log("SCAN", "Virus Detected", source=norm_path, file_hash=self.calc_file_hash(norm_path))
                    
                    self.cloud_check(norm_path)
                except Exception as e:
                    self.write_log("WARN", "Scan Engine", source=norm_path, detail=str(e), success=False)

                finally:
                    if was_locked:
                        self.lock_file(norm_path, True)

        finally:
            with self.lock_virus:
                self.scan_running = False
                self.scan_finished = True
                count, scanned, elapsed = len(self.virus_results), self.scan_count, int(time.time() - self.scan_start)

            messages = {
                "traditional_switch": f"發現 {count} 個病毒，掃描 {scanned} 個檔案，耗時 {elapsed} 秒",
                "simplified_switch": f"发现 {count} 个病毒，扫描 {scanned} 个文件，耗时 {elapsed} 秒",
                "english_switch": f"Found {count} viruses, scanned {scanned} files, time {elapsed}s",
                "japanese_switch": f"{count} 個のウイルスを発見し、{scanned} 個のファイルをスキャンしました（所要時間 {elapsed} 秒）",
                "korean_switch": f"바이러스 {count}개 발견, 파일 {scanned}개 검사, 소요 시간 {elapsed}초",
                "french_switch": f"{count} virus trouvés, {scanned} fichiers analysés, temps {elapsed}s",
                "spanish_switch": f"Se encontraron {count} virus, {scanned} archivos escaneados, tiempo {elapsed}s",
                "hindi_switch": f"{count} वायरस मिले, {scanned} फ़ाइलें स्कैन की गईं, समय {elapsed}s",
                "arabic_switch": f"تم العثور على {count} فيروسات، تم فحص {scanned} ملفات، الوقت {elapsed} ثانية",
                "russian_switch": f"Найдено {count} вирусов, проверено {scanned} файлов, время {elapsed}с",
                "slovenian_switch": f"Najdenih {count} virusov, skeniranih {scanned} datotek, čas {elapsed}s"
            }
            if self._window:
                js_cmd = f"if(window.finishScan) window.finishScan({json.dumps(messages)}, {count});"
                self.ui_queue.put(js_cmd)

            self.write_log("INFO", "Scan Completed", detail=f"Found {count} viruses, scanned {scanned} files, time {elapsed}s")

    def stop_scan(self):
        with self.lock_virus: self.scan_running = False

    def trigger_scan(self, method):
        messages = {
            "traditional_switch": "已取消掃描",
            "simplified_switch": "已取消扫描", "english_switch":
            "Scan cancelled", "japanese_switch": "スキャンがキャンセルされました",
            "korean_switch": "스캔이 취소되었습니다",
            "french_switch": "Analyse annulée",
            "spanish_switch": "Escaneo cancelado",
            "hindi_switch": "स्कैन रद्द कर दिया गया",
            "arabic_switch": "تم إلغاء الفحص",
            "russian_switch": "Сканирование отменено",
            "slovenian_switch": "Skeniranje preklicano"
        }
        targets = []
        
        if method == "smart":
            for folder in ["Desktop", "Downloads", "AppData"]:
                fp = os.path.join(self.path_user, folder)
                if os.path.exists(fp):
                    targets.append(fp)

            if os.path.exists(self.path_config):
                targets.append(self.path_config)

            for proc in self.get_process_list():
                if proc["path"] and proc["path"] != "None": targets.append(proc["path"])

            self.start_scan(list(set(targets)))

        elif method == "file":
            targets = self.select_files()
            if targets:
                self.start_scan(targets)

            elif self._window:
                self._window.evaluate_js(f"if(window.finishScan) window.finishScan({json.dumps(messages)}, 0);")

        elif method == "path":
            targets = self.select_folder()
            if targets:
                self.start_scan(targets)

            elif self._window:
                self._window.evaluate_js(f"if(window.finishScan) window.finishScan({json.dumps(messages)}, 0);")

        elif method == "full":
            targets = [f"{chr(d)}:/" for d in range(65, 91) if os.path.exists(f"{chr(d)}:/")]
            self.start_scan(targets)

    def solve_scan(self, file_paths):
        deleted_paths = []
        proc_map = {}
        for proc in self.get_process_list():
            if proc["path"] and proc["path"] != "None":

                norm_p = self.norm_path(proc["path"], must_exist=False)
                if norm_p:
                    proc_map.setdefault(os.path.normcase(norm_p), []).append(proc["pid"])

        last_update = 0.0
        with self.lock_virus:
            deleted_set = set()
            for raw_path in file_paths:

                path = self.norm_path(raw_path, must_exist=False)
                if not path:
                    continue

                current_time = time.time()
                if current_time - last_update >= 0.05:
                    if self._window:
                        self._window.evaluate_js(f"if(window.updateDeleteProgress) window.updateDeleteProgress({json.dumps(path.replace(os.sep, '/'))});")

                    last_update = current_time
                    
                try:
                    if path in self.virus_lock:
                        self.lock_file(path, False)

                    path_key = os.path.normcase(path)
                    if path_key in proc_map:
                        for pid in proc_map[path_key]:
                            self.kill_process(pid)

                    try:
                        os.chmod(path, stat.S_IWRITE)
                    except Exception:
                        pass

                    delete_success = False
                    for _ in range(5):
                        try:
                            os.remove(path)
                            delete_success = True
                            break

                        except Exception:
                            time.sleep(0.1)
                            
                    if not delete_success:
                        os.remove(path)

                    self.remove_list_items("quarantine", [path])
                    deleted_paths.append(raw_path) 
                    deleted_set.add(path)
                    self.write_log("INFO", "Virus Delete", source=path, file_hash=self.calc_file_hash(path), operate=True, success=True)

                except Exception as e:
                    self.lock_file(path, True)
                    self.write_log("SCAN", "Virus Delete", source=path, file_hash=self.calc_file_hash(path), detail=str(e), operate=True, success=False)

            if deleted_set:
                self.virus_results = [p for p in self.virus_results if p not in deleted_set]

            remaining = len(self.virus_results)

        messages = {
            "traditional_switch": f"剩餘 {remaining} 個病毒，已刪除 {len(deleted_paths)} 個檔案。",
            "simplified_switch": f"剩余 {remaining} 个病毒，已删除 {len(deleted_paths)} 个文件。",
            "english_switch": f"Remaining {remaining} viruses, deleted {len(deleted_paths)} files.",
            "japanese_switch": f"残りのウイルス {remaining} 個、削除されたファイル {len(deleted_paths)} 個。",
            "korean_switch": f"남은 바이러스 {remaining}개, 삭제된 파일 {len(deleted_paths)}개.",
            "french_switch": f"Virus restants : {remaining}, fichiers supprimés : {len(deleted_paths)}.",
            "spanish_switch": f"Virus restantes: {remaining}, archivos eliminados: {len(deleted_paths)}.",
            "hindi_switch": f"शेष वायरस {remaining}, हटाए गए फ़ाइलें {len(deleted_paths)}.",
            "arabic_switch": f"الفيروسات المتبقية {remaining}، تم حذف {len(deleted_paths)} ملفات.",
            "russian_switch": f"Осталось вирусов: {remaining}, удалено файлов: {len(deleted_paths)}.",
            "slovenian_switch": f"Preostalih virusov: {remaining}, izbrisanih datotek: {len(deleted_paths)}."
        }
        if self._window:
            self._window.evaluate_js(f"if(window.finishScan) window.finishScan({json.dumps(messages)}, {remaining});")

        return deleted_paths

    def remove_virus_result(self, paths):
        with self.lock_virus:
            norm_paths = set(self.norm_path(p, must_exist=False) for p in paths)
            self.virus_results = [p for p in self.virus_results if p not in norm_paths]
            return len(self.virus_results)

    def cloud_check(self, file_path):
        norm_path = self.norm_path(file_path)
        if not norm_path:
            return
            
        cache_key = os.path.normcase(norm_path)
        with self.lock_file_ops:
            if cache_key in self.cloud_pending:
                return

            self.cloud_pending.add(cache_key)
            
        self.cloud_queue.put(norm_path)

    def cloud_worker(self):
        while True:
            try:
                file_path = self.cloud_queue.get()
                cache_key = os.path.normcase(file_path)

                try:
                    self.perform_cloud_scan(file_path)
                finally:
                    with self.lock_file_ops:
                        self.cloud_pending.discard(cache_key)

                    self.cloud_queue.task_done()
            except Exception:
                pass

    def perform_cloud_scan(self, file_path):
        was_locked = False
        try:
            with self.lock_config:
                if not self.pyas_config.get("cloud_switch", True):
                    return False

                api_host, api_key, max_size = self.pyas_config.get("api_host"), self.pyas_config.get("api_key"), self.pyas_config.get("size", 256 * 1024 * 1024)

            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                return False

            with self.lock_file_ops:
                if file_path in self.virus_lock:
                    self.lock_file(file_path, False)
                    was_locked = True

            if os.path.getsize(file_path) > max_size:
                if was_locked:
                    self.lock_file(file_path, True)
                return False

            file_hash = self.calc_file_hash(file_path)
            success, sha256 = self.cloud.upload_file(file_path, api_host, api_key, file_hash=file_hash)
            if was_locked:
                self.lock_file(file_path, True)
                was_locked = False

            if not success:
                self.write_log("WARN", "Cloud API", source=file_path, detail="Failed", success=False)

        except Exception as e:
            self.write_log("WARN", "perform_cloud_scan", detail=str(e), success=False)

        finally:
            if was_locked:
                try:
                    self.lock_file(file_path, True)
                except Exception:
                    pass
        return False

####################################################################################################

    def is_in_whitelist(self, file_path):
        p = self.norm_path(file_path, must_exist=False)
        if not p: 
            return False
            
        p_norm = os.path.normcase(p)
        
        with self.lock_config: 
            whitelist = self.pyas_config.get("white_list", [])
            
        for item in whitelist:
            if isinstance(item, dict):
                wl_path = item.get("file", "")
                wl_norm = self.norm_path(wl_path, must_exist=False)
                if not wl_norm:
                    continue
                    
                wl_norm = os.path.normcase(wl_norm)
                
                if p_norm == wl_norm:
                    return True
                    
                if not wl_norm.endswith(os.sep):
                    wl_norm += os.sep
                    
                if p_norm.startswith(wl_norm):
                    return True
                    
        return False

    def init_whitelist(self):
        self.manage_named_list("white_list", [self.file_pyas], action="add")

    def sync_driver_whitelist(self, file_path, is_add=True):
        with self.lock_driver:
            if not self.driver_port:
                return False

            driver_path = str(file_path)
            drive_letter = os.path.splitdrive(driver_path)[0]
            if drive_letter:
                driver_path = "*" + driver_path[len(drive_letter):]

            msg = PYAS_USER_MESSAGE()
            msg.Command = 1 if is_add else 2
            msg.Path = driver_path
            bytes_returned = ctypes.wintypes.DWORD(0)

            try:
                return self.fltlib.FilterSendMessage(self.driver_port, ctypes.byref(msg), ctypes.sizeof(msg), None, 0, ctypes.byref(bytes_returned)) == 0
            except Exception:
                return False

    def lock_file(self, target_path, lock, quiet=False):
        with self.lock_file_ops:
            if lock:
                if not os.path.exists(target_path):
                    return
                
                paths_to_lock = []
                if os.path.isdir(target_path):
                    for root, _, files in os.walk(target_path):
                        for f in files:
                            paths_to_lock.append(os.path.join(root, f))
                else:
                    paths_to_lock.append(target_path)

                for file_path in paths_to_lock:
                    if file_path in self.virus_lock:
                        continue
                        
                    success = False
                    last_error = None
                    for _ in range(5):
                        try:
                            fd = os.open(file_path, os.O_RDWR | os.O_BINARY)
                            try:
                                try:
                                    size = os.path.getsize(file_path)
                                except Exception:
                                    size = 1

                                lock_size = size if size > 0 else 1
                                msvcrt.locking(fd, msvcrt.LK_NBRLCK, lock_size)
                                self.virus_lock[file_path] = (fd, lock_size)
                                success = True
                                break

                            except Exception as e:
                                os.close(fd)
                                raise e

                        except Exception as e:
                            last_error = e
                            time.sleep(0.1)
                            
                    if not success and not quiet:
                        self.write_log("WARN", "lock_file", source=file_path, detail=str(last_error), success=False)
            else:
                target_norm = os.path.normcase(target_path)
                target_dir = target_norm + os.sep
                keys_to_unlock = []
                
                for locked_path in self.virus_lock:
                    locked_norm = os.path.normcase(locked_path)
                    if locked_norm == target_norm or locked_norm.startswith(target_dir):
                        keys_to_unlock.append(locked_path)

                for file_path in keys_to_unlock:
                    fd, lock_size = self.virus_lock[file_path]
                    try:
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, lock_size)
                    except Exception as e:
                        if not quiet:
                            self.write_log("WARN", "unlock_file", source=file_path, detail=str(e), success=False)

                    finally:
                        try:
                            os.close(fd)
                        except Exception:
                            pass
                        del self.virus_lock[file_path]

    def relock_file(self):
        while True:
            try:
                with self.lock_config:
                    quarantine_list = self.pyas_config.get("quarantine", [])
                
                with self.lock_file_ops:
                    locked_keys = set(self.virus_lock.keys())

                for item in quarantine_list:
                    file_path = item.get("file")
                    if not file_path or not os.path.exists(file_path):
                        continue
                        
                    if os.path.isdir(file_path):
                        self.lock_file(file_path, True, quiet=True)
                    elif file_path not in locked_keys:
                        self.lock_file(file_path, True, quiet=True)

            except Exception:
                pass
            time.sleep(5)

    def backup_mbr(self, max_drives=26):
        self.mbr_backup = {}
        for drive in range(max_drives):
            try:
                with open(rf"\\.\PhysicalDrive{drive}", "rb") as f:
                    mbr = f.read(512)
                    if len(mbr) == 512 and mbr[510:512] == b"\x55\xAA":
                        self.mbr_backup[drive] = mbr

            except Exception:
                continue

    def check_system_mbr(self):
        for drive, mbr_value in list(self.mbr_backup.items()):
            try:
                with open(rf"\\.\PhysicalDrive{drive}", "rb") as f:
                    if f.read(512) != mbr_value:
                        return True

            except Exception:
                pass
        return False

    def _get_restrict_lists(self):
        permissions = [
            "NoControlPanel", "NoDrives", "NoFileMenu", "NoFind", "NoStartMenuPinnedList", "NoSetFolders", "NoSetFolderOptions", "NoViewOnDrive", "NoClose", "NoDesktop",
            "NoLogoff", "NoFolderOptions", "RestrictRun", "NoViewContextMenu", "HideClock", "NoStartMenuMyGames", "NoStartMenuMyMusic", "DisableCMD", "NoAddingComponents",
            "NoWinKeys", "NoStartMenuLogOff", "NoSimpleNetIDList", "NoLowDiskSpaceChecks", "DisableLockWorkstation","Restrict_Run", "DisableTaskMgr", "DisableRegistryTools",
            "DisableChangePassword", "Wallpaper", "NoComponents", "NoStartMenuMorePrograms", "NoActiveDesktop", "NoSetActiveDesktop", "NoRecentDocsMenu", "NoWindowsUpdate",
            "NoChangeStartMenu", "NoFavoritesMenu", "NoRecentDocsHistory", "NoSetTaskbar", "NoSMHelp", "NoTrayContextMenu", "NoManageMyComputerVerb", "NoRealMode", "NoRun",
            "ClearRecentDocsOnExit", "NoActiveDesktopChanges", "NoStartMenuNetworkPlaces"
        ]
        paths = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\MMC"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\Windows\System"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System")
        ]
        return permissions, paths

    def check_system_restrict(self):
        permissions, paths = self._get_restrict_lists()
        for hkey, path in paths:
            for val in permissions:
                if self._reg_read(hkey, path, val) is not None:
                    return True

        return False

    def check_system_file_type(self):
        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for ext in [".exe", ".bat", ".cmd", ".com"]:
                if self._reg_read(root, rf"SOFTWARE\Classes\{ext}", "") != ("exefile" if ext == ".exe" else ext[1:]+"file"):
                    return True

            for cmd in ["open", "runas"]:
                if self._reg_read(root, rf"SOFTWARE\Classes\exefile\shell\{cmd}\command", "") != '"%1" %*':
                    return True

        return False

    def check_system_file_icon(self):
        return any(self._reg_read(root, r"SOFTWARE\Classes\exefile\DefaultIcon", "") != "%1" for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER])

    def check_system_image(self):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", 0, winreg.KEY_READ) as reg:
                i = 0
                while True:
                    try:
                        subkey = winreg.EnumKey(reg, i)
                        with winreg.OpenKey(reg, subkey, 0, winreg.KEY_READ) as sub_reg:
                            for val in ["Debugger", "UseFilter", "GlobalFlag", "MitigationOptions"]:
                                try:
                                    winreg.QueryValueEx(sub_reg, val);
                                    return True

                                except FileNotFoundError:
                                    pass

                        i += 1
                    except OSError:
                        break

        except Exception:
            pass
        return False

    def check_system_wallpaper(self):
        return self._reg_read(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "Wallpaper") != os.path.join(self.path_system, "web", "wallpaper", "Windows", "img0.jpg")

    def scan_system_repair(self):
        items = []

        for drive, mbr_value in list(self.mbr_backup.items()):
            drive_path = rf"\\.\PhysicalDrive{drive}"
            try:
                with open(drive_path, "rb") as f:
                    if f.read(512) != mbr_value:
                        items.append({"id": f"mbr|{drive}", "display": "repair_mbr", "path": drive_path})

            except Exception:
                pass

        permissions, paths = self._get_restrict_lists()
        for hkey, path in paths:
            for val in permissions:

                if self._reg_read(hkey, path, val) is not None:
                    root = "HKLM" if hkey == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                    items.append({"id": f"restrict|{root}\\{path}\\{val}", "display": "repair_limit", "path": rf"{root}\{path}\{val}"})

        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            root_str = "HKLM" if root == winreg.HKEY_LOCAL_MACHINE else "HKCU"

            for ext in [".exe", ".bat", ".cmd", ".com"]:
                expected = "exefile" if ext == ".exe" else ext[1:] + "file"
                if self._reg_read(root, rf"SOFTWARE\Classes\{ext}", "") != expected:
                    items.append({"id": f"file_type|{root_str}\\{ext}", "display": "repair_assoc", "path": rf"{root_str}\SOFTWARE\Classes\{ext}"})

            for cmd in ["open", "runas"]:
                if self._reg_read(root, rf"SOFTWARE\Classes\exefile\shell\{cmd}\command", "") != '"%1" %*':
                    items.append({"id": f"file_type|{root_str}\\exefile\\{cmd}", "display": "repair_assoc", "path": rf"{root_str}\SOFTWARE\Classes\exefile\shell\{cmd}\command"})

            if self._reg_read(root, r"SOFTWARE\Classes\exefile\DefaultIcon", "") != "%1":
                items.append({"id": f"file_icon|{root_str}", "display": "repair_icon", "path": rf"{root_str}\SOFTWARE\Classes\exefile\DefaultIcon"})

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", 0, winreg.KEY_READ) as reg:
                i = 0
                while True:
                    try:
                        subkey = winreg.EnumKey(reg, i)
                        with winreg.OpenKey(reg, subkey, 0, winreg.KEY_READ) as sub_reg:
                            for val in ["Debugger", "UseFilter", "GlobalFlag", "MitigationOptions"]:
                                try:
                                    winreg.QueryValueEx(sub_reg, val)
                                    items.append({"id": f"image|{subkey}", "display": "repair_hijack", "path": rf"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{subkey}"})
                                    break
                                except FileNotFoundError:
                                    pass

                        i += 1
                    except OSError:
                        break

        except Exception:
            pass

        wp = self._reg_read(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "Wallpaper")
        expected_wp = os.path.join(self.path_system, "web", "wallpaper", "Windows", "img0.jpg")
        if wp != expected_wp:
            items.append({"id": "wallpaper|0", "display": "repair_wallpaper", "path": wp if wp else r"HKCU\Control Panel\Desktop\Wallpaper"})

        return items

    def repair_system_mbr(self):
        for drive, mbr_value in list(self.mbr_backup.items()):
            drive_path = rf"\\.\PhysicalDrive{drive}"
            try:
                with open(drive_path, "rb+") as f:
                    if f.read(512) != mbr_value:
                        f.seek(0); f.write(mbr_value)
                        self.write_log("INFO", "MBR Repaired", source=drive_path, operate=True)

            except Exception:
                pass

    def repair_system_restrict(self):
        permissions, paths = self._get_restrict_lists()
        for hkey, path in paths:
            for val in permissions:
                self._reg_delete(hkey, path, val)

    def repair_system_file_type(self):
        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for ext in [".exe", ".bat", ".cmd", ".com"]:
                self._reg_write(root, rf"SOFTWARE\Classes\{ext}", None, winreg.REG_SZ, "exefile" if ext == ".exe" else ext[1:]+"file")

            for cmd in ["open", "runas"]:
                self._reg_write(root, rf"SOFTWARE\Classes\exefile\shell\{cmd}\command", None, winreg.REG_SZ, '"%1" %*')

    def repair_system_file_icon(self):
        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]: self._reg_write(root, r"SOFTWARE\Classes\exefile\DefaultIcon", None, winreg.REG_SZ, "%1")

    def repair_system_image(self):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", 0, winreg.KEY_ALL_ACCESS) as reg:
                i = 0
                while True:
                    try:
                        subkey = winreg.EnumKey(reg, i)
                        with winreg.OpenKey(reg, subkey, 0, winreg.KEY_ALL_ACCESS) as sub_reg:
                            for val in ["Debugger", "UseFilter", "GlobalFlag", "MitigationOptions"]:
                                try:
                                    winreg.DeleteValue(sub_reg, val)
                                except FileNotFoundError:
                                    pass

                        i += 1
                    except OSError:
                        break

        except Exception as e:
            self.write_log("WARN", "repair_system_image", detail=str(e), success=False)

    def repair_system_wallpaper(self):
        try:
            wallpaper = os.path.join(self.path_system, "web", "wallpaper", "Windows", "img0.jpg")
            if not os.path.exists(wallpaper):
                return

            self._reg_write(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "Wallpaper", winreg.REG_SZ, wallpaper)
            theme_dir = os.path.join(self.path_appdata, "Microsoft", "Windows", "Themes")

            for fname in ["TranscodedWallpaper", "TranscodedWallpaper.tmp"]:
                try:
                    os.remove(os.path.join(theme_dir, fname))
                except Exception:
                    pass

            shutil.rmtree(os.path.join(theme_dir, "CachedFiles"), ignore_errors=True)
            self.user32.SystemParametersInfoW(20, 0, wallpaper, 3)

        except Exception as e:
            self.write_log("WARN", "repair_system_wallpaper", detail=str(e), success=False)

    def execute_system_repair(self, items):
        try:
            types = set(item.split('|')[0] for item in items)

            if "mbr" in types:
                self.repair_system_mbr()
            if "restrict" in types:
                self.repair_system_restrict()
            if "file_type" in types:
                self.repair_system_file_type()
            if "file_icon" in types:
                self.repair_system_file_icon()
            if "image" in types:
                self.repair_system_image()
            if "wallpaper" in types:
                self.repair_system_wallpaper()

            self.write_log("INFO", "System Repair", detail=f"Repaired {len(items)} items", operate=True)
            return True

        except Exception as e:
            self.write_log("WARN", "execute_system_repair", detail=str(e), operate=True, success=False)
            return False

    def protect_proc_thread(self):
        with self.lock_proc:
            self.exist_process = self.get_process_list_pids()

        while True:
            with self.lock_config:
                if not self.pyas_config.get("process_switch", False):
                    break
            try:
                time.sleep(0.1)
                cur = self.get_process_list_pids()

                with self.lock_proc:
                    new_pids = cur - self.exist_process
                    self.exist_process = cur

                for pid in new_pids:
                    h = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
                    if h:
                        with self.lock_config:
                            should_suspend = self.pyas_config.get("suspend_switch", True)
                        
                        if should_suspend:
                            self.ntdll.NtSuspendProcess(h)
                            with self.lock_proc:
                                self.suspended_procs.add(h)
                        try:
                            self.proc_pool.submit(self.handle_new_process, pid, h, should_suspend)

                        except Exception:
                            if should_suspend:
                                self.ntdll.NtResumeProcess(h)
                                with self.lock_proc:
                                    self.suspended_procs.discard(h)

                            self.kernel32.CloseHandle(h)
            except Exception as e:
                self.write_log("WARN", "protect_proc_thread", detail=str(e), success=False)

    def handle_new_process(self, pid, h=None, suspended=None):
        if suspended is None:
            with self.lock_config:
                suspended = self.pyas_config.get("suspend_switch", True)

        if not h:
            h = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if not h:
                return

            if suspended:
                self.ntdll.NtSuspendProcess(h)
                with self.lock_proc:
                    if not hasattr(self, 'suspended_procs'):
                        self.suspended_procs = set()
                    self.suspended_procs.add(h)
        try:
            cmdline = self.get_process_cmdline(h)
            process_file = self.get_process_file(h)
            if "-scan" in cmdline and self.path_equal(process_file, self.file_pyas): return

            raw_targets = self.extract_paths_from_cmdline(cmdline)
            if process_file:
                raw_targets.append(process_file)

            all_targets = []
            for p in raw_targets:
                np = self.norm_path(self.device_path_to_drive(p))
                if np and np not in all_targets:
                    all_targets.append(np)

            with self.lock_config:
                ext_filter = self.pyas_config.get("suffix_switch", True)
                suffix = self.pyas_config.get("suffix", [])

            scan_targets = []
            for file_path in all_targets:
                if not file_path or not os.path.isfile(file_path):
                    continue
                if ext_filter and os.path.splitext(file_path)[-1].lower() not in suffix:
                    continue
                if self.is_in_whitelist(file_path):
                    continue
                if process_file and process_file.lower().endswith("explorer.exe") and "/select" in cmdline.lower():
                    continue
                scan_targets.append(file_path)

            if not scan_targets:
                return

            virus_found = False
            for file_path in scan_targets:
                result = self.safe_scan_engine(file_path)
                self.cloud_check(file_path)
                
                if result:
                    self.kernel32.TerminateProcess(h, 0)
                    self.write_log("BLOCK", "Process Block", pid=pid, source=file_path, file_hash=self.calc_file_hash(file_path))
                    virus_found = True
                    break
            
            if not virus_found:
                hidden_virus_path = self.scan_process_memory(pid, h)
                if hidden_virus_path:
                    self.kernel32.TerminateProcess(h, 0)
                    self.write_log("BLOCK", "Process DLL Block", pid=pid, source=hidden_virus_path, file_hash=self.calc_file_hash(hidden_virus_path))

        finally:
            if suspended:
                try:
                    self.ntdll.NtResumeProcess(h)
                except Exception:
                    pass
                with self.lock_proc:
                    self.suspended_procs.discard(h)
            try:
                self.kernel32.CloseHandle(h)
            except Exception:
                pass

    def scan_process_memory(self, pid, h_process):
        scanned_paths = set()
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        system_dir = self.path_system.lower()
        
        buf = ctypes.create_unicode_buffer(1024)
        max_address = 0x7FFFFFFFFFFF if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x7FFFFFFF

        with self.lock_config:
            ext_filter = self.pyas_config.get("suffix_switch", True)
            suffix = self.pyas_config.get("suffix", [])

        try:
            while address < max_address and self.kernel32.VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                if mbi.State == 0x1000 and mbi.Type == 0x1000000:
                    if self.psapi.GetMappedFileNameW(h_process, ctypes.c_void_p(address), buf, 1024):

                        raw_path = buf.value
                        if raw_path.startswith("\\"):
                            raw_path = self.device_path_to_drive(raw_path)

                        file_path = self.norm_path(raw_path)
                        if file_path and file_path not in scanned_paths:

                            scanned_paths.add(file_path)
                            file_path_lower = file_path.lower()
                            
                            if not file_path_lower.startswith(system_dir) and not self.is_in_whitelist(file_path):
                                ext = os.path.splitext(file_path_lower)[-1]

                                if ext != ".exe" and (not ext_filter or ext in suffix):
                                    if self.safe_scan_engine(file_path):
                                        return file_path

                                    self.cloud_check(file_path)
                
                if mbi.RegionSize == 0:
                    break
                address += mbi.RegionSize
                
        finally:
            scanned_paths.clear()
            
        return None

    def protect_file_thread(self):
        with self.lock_file_ops:
            if getattr(self, 'h_dir_file', None):
                return
            
        hDir = self.kernel32.CreateFileW(self.path_user, 0x0001, 0x00000007, None, 3, 0x02000000, None)
        if not hDir or hDir == -1:
            return

        with self.lock_file_ops:
            self.h_dir_file = hDir

        try:
            buffer = ctypes.create_string_buffer(262144)
            temp_prefix = os.path.normcase(self.path_temp)
            if not temp_prefix.endswith(os.sep):
                temp_prefix += os.sep

            while True:
                with self.lock_config:
                    if not self.pyas_config.get("document_switch", False): 
                        break
                try:
                    bytes_returned = ctypes.wintypes.DWORD()
                    res = self.kernel32.ReadDirectoryChangesW(self.h_dir_file, buffer, ctypes.sizeof(buffer), True, 0x0000001F, ctypes.byref(bytes_returned), None, None)
                    if not res or bytes_returned.value == 0:
                        break

                    offset = 0
                    while True:
                        notify = FILE_NOTIFY_INFORMATION.from_buffer(buffer, offset)
                        raw_filename = notify.FileName[:notify.FileNameLength // 2]

                        if raw_filename and notify.Action in [1, 3, 5]:
                            file_path = self.norm_path(os.path.join(self.path_user, raw_filename), must_exist=True)

                            if file_path and not self.is_in_whitelist(file_path):
                                norm_path = os.path.normcase(file_path)

                                if not (norm_path.startswith(temp_prefix) and norm_path[len(temp_prefix):].startswith("_mei")):
                                    with self.lock_config:
                                        ext_filter = self.pyas_config.get("suffix_switch", True)
                                        suffix = self.pyas_config.get("suffix", [])

                                    if not ext_filter or os.path.splitext(file_path)[-1].lower() in suffix:
                                        self.protect_pool.submit(self.handle_new_file, file_path)

                        if notify.NextEntryOffset == 0:
                            break

                        offset += notify.NextEntryOffset

                except Exception:
                    break
        finally:
            with self.lock_file_ops:
                if getattr(self, 'h_dir_file', None):
                    try:
                        self.kernel32.CloseHandle(self.h_dir_file)
                    except Exception:
                        pass
                    self.h_dir_file = None

    def handle_new_file(self, file_path):
        try:
            for _ in range(5):
                try:
                    fd = os.open(file_path, os.O_RDONLY | os.O_BINARY)
                    os.close(fd)

                    size = os.path.getsize(file_path)
                    if size > 0:
                        break

                except Exception:
                    pass
                time.sleep(0.1)
            else:
                return

            with self.lock_file_ops:
                if file_path in self.virus_lock: return

            result = self.safe_scan_engine(file_path)
            self.cloud_check(file_path)
            
            if result:
                if self.manage_named_list("quarantine", [file_path], action="add", lock_func=self.lock_file) > 0:
                    self.write_log("BLOCK", "File Block", source=file_path, file_hash=self.calc_file_hash(file_path))

        except Exception:
            pass

    def protect_net_thread(self):
        with self.lock_net:
            self.exist_connections = set()

        while True:
            with self.lock_config:
                if not self.pyas_config.get("network_switch", False): break

            try:
                time.sleep(0.5)
                conns = self.get_connections_list()

                with self.lock_net:
                    new_conns = conns - self.exist_connections
                    self.exist_connections = conns

                for key in new_conns:
                    self.protect_pool.submit(self.handle_new_connection, key)

            except Exception as e:
                self.write_log("WARN", "protect_net_thread", detail=str(e), success=False)

        with self.lock_net:
            self.exist_connections = set()

    def handle_new_connection(self, key):
        pid, remote_addr, remote_port = key
        try:
            h = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if not h:
                return

            try:
                remote_ip = f"{remote_addr & 0xFF}.{(remote_addr >> 8) & 0xFF}.{(remote_addr >> 16) & 0xFF}.{(remote_addr >> 24) & 0xFF}"
                file_path = self.norm_path(self.get_process_file(h))

                if file_path and not self.is_in_whitelist(file_path) and hasattr(self.heuristic, "network") and remote_ip in self.heuristic.network:
                    self.kernel32.TerminateProcess(h, 0)
                    self.write_log("BLOCK", "Network Block", pid=pid, source=file_path, target=remote_ip, file_hash=self.calc_file_hash(file_path))

            finally:
                self.kernel32.CloseHandle(h)

        except Exception as e:
            self.write_log("WARN", "handle_new_connection", pid=pid, detail=str(e), success=False)

    def protect_system_thread(self):
        while True:
            with self.lock_config:
                if not self.pyas_config.get("system_switch", False):
                    break
            try:
                self.repair_system_mbr()
                self.repair_system_restrict()
                self.repair_system_file_type()
                self.repair_system_file_icon()
                self.repair_system_image()
                self.check_process_survival()
                time.sleep(0.5)

            except Exception as e:
                self.write_log("WARN", "protect_system_thread", detail=str(e), success=False)

    def check_process_survival(self):
        try:
            running = any(exe_name.lower() == "explorer.exe" for _, exe_name in self._enum_processes())

            if not running:
                subprocess.Popen("explorer.exe", shell=True)
                self.write_log("INFO", "System Restart", source="explorer.exe")

        except Exception:
            pass

    def capture_popup_window(self):
        try:
            start_time = time.time()
            while time.time() - start_time < 5:

                hwnd = self.user32.GetForegroundWindow()
                if not hwnd:
                    time.sleep(0.5)
                    continue

                pid = ctypes.c_ulong(0)
                self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value != self.pid_pyas and pid.value > 4:

                    length = self.user32.GetWindowTextLengthW(hwnd)
                    title, class_name = ctypes.create_unicode_buffer(length + 1), ctypes.create_unicode_buffer(256)
                    self.user32.GetWindowTextW(hwnd, title, length + 1)
                    self.user32.GetClassNameW(hwnd, class_name, 256)

                    proc_name, _ = self.get_exe_info(pid.value)
                    t_str, c_str = str(title.value), str(class_name.value)

                    if proc_name and not any(item.get("exe") == proc_name or item.get("class") == c_str for item in self.pass_windows):
                        return {"exe": proc_name, "class": c_str, "title": t_str}

                time.sleep(0.5)

        except Exception as e:
            self.write_log("WARN", "capture_popup_window", detail=str(e), success=False)
        return None

    def add_popup_rule(self, rule):
        if not rule:
            return False

        with self.lock_config:
            target_list = self.pyas_config.setdefault("block_list", [])
            if any(item.get("exe") == rule.get("exe") and item.get("class") == rule.get("class") and item.get("title") == rule.get("title") for item in target_list):
                return False

            target_list.append(rule)
            self.write_log("INFO", "Config Update", detail=f"List [block_list] add: {rule}")
            self.save_config()
            return True

    def popup_intercept_thread(self):
        hwnd_list = []

        def enum_windows_callback(hWnd, lParam):
            if self.user32.IsWindowVisible(hWnd):
                hwnd_list.append(hWnd)
            return True
            
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
        self._enum_cb_keepalive = WNDENUMPROC(enum_windows_callback)

        while True:
            try:
                time.sleep(0.5)
                with self.lock_config:
                    rules = self.pyas_config.get("block_list", [])
                if not rules:
                    continue

                hwnd_list.clear()
                self.user32.EnumWindows(self._enum_cb_keepalive, 0)
                
                for hWnd in list(hwnd_list):
                    pid = ctypes.c_ulong(0)
                    self.user32.GetWindowThreadProcessId(hWnd, ctypes.byref(pid))
                    if pid.value <= 4:
                        continue

                    proc_name, _ = self.get_exe_info(pid.value)
                    length = self.user32.GetWindowTextLengthW(hWnd)
                    title, class_name = ctypes.create_unicode_buffer(length + 1), ctypes.create_unicode_buffer(256)

                    self.user32.GetWindowTextW(hWnd, title, length + 1)
                    self.user32.GetClassNameW(hWnd, class_name, 256)
                    t_str, c_str = str(title.value), str(class_name.value)

                    if any(item.get("exe") == proc_name or item.get("class") == c_str for item in self.pass_windows):
                        continue
                    
                    is_block = False
                    for item in rules:
                        if item.get("exe") and item.get("exe") == proc_name and (item.get("class") == c_str or item.get("title") == t_str):
                            is_block = True
                            break

                    if is_block:
                        for msg in [0x0010, 0x0002, 0x0012, 0x0112]:
                            self.user32.SendMessageW(hWnd, msg, 0xF060, 0)
                        if proc_name:
                            self.kill_process(pid.value)

            except Exception:
                pass

    def install_system_driver(self):
        try:
            service_name = "PYAS_Driver"
            subprocess.run(f'sc create {service_name} binPath="{self.path_drivers}" type=kernel start=demand error=normal depend=FltMgr group="FSFilter Activity Monitor"', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)

            self._reg_write(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\PYAS_Driver\Instances", "DefaultInstance", winreg.REG_SZ, "PYAS Instance")
            self._reg_write(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\PYAS_Driver\Instances\PYAS Instance", "Altitude", winreg.REG_SZ, "320000")
            self._reg_write(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\PYAS_Driver\Instances\PYAS Instance", "Flags", winreg.REG_DWORD, 0)

            subprocess.run(["sc", "start", service_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
            return self.check_system_driver()

        except Exception:
            return False

    def stop_system_driver(self):
        try:
            with self.lock_driver:
                if self.driver_port:
                    try:
                        self.kernel32.CloseHandle(self.driver_port)
                    except Exception:
                        pass
                    self.driver_port = None

            subprocess.run(["sc", "stop", "PYAS_Driver"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)

            for _ in range(5):
                res = subprocess.run(["sc", "query", "PYAS_Driver"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
                if "STOPPED" in res.stdout or "FAILED" in res.stderr or "1060" in res.stdout:
                    break

                time.sleep(0.1)

            subprocess.run(["sc", "delete", "PYAS_Driver"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
            return True
        except Exception:
            return False

    def check_system_driver(self):
        try:
            return "RUNNING" in subprocess.run(["sc", "query", "PYAS_Driver"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True).stdout
        except Exception:
            return False

    def pipe_server_thread(self):
        try:
            while True:
                with self.lock_config:
                    if not self.pyas_config.get("driver_switch", False):
                        break

                temp_port = ctypes.wintypes.HANDLE()
                if self.fltlib.FilterConnectCommunicationPort("\\PYAS_Output_Pipe", 0, None, 0, None, ctypes.byref(temp_port)) == 0:
                    with self.lock_driver:
                        self.driver_port = temp_port

                    with self.lock_config:
                        whitelist = self.pyas_config.get("white_list", [])

                    for item in whitelist:
                        if isinstance(item, dict) and item.get("file"): self.sync_driver_whitelist(item["file"], True)

                    message = PYAS_FULL_MESSAGE()
                    while True:
                        with self.lock_config:
                            if not self.pyas_config.get("driver_switch", False):
                                break

                        with self.lock_driver:
                            current_port = self.driver_port
                        if not current_port:
                            break

                        try:
                            if self.fltlib.FilterGetMessage(current_port, ctypes.byref(message), ctypes.sizeof(PYAS_FULL_MESSAGE), None) == 0:
                                code, pid, target = message.Data.MessageCode, message.Data.ProcessId, message.Data.Path
                                exe_info = self.get_exe_info(pid)
                                safe_source = exe_info[1] if exe_info and exe_info[1] else "Unknown"

                                with self.lock_config:
                                    block_codes = self.pyas_config.get("block", [])

                                if code in block_codes and not self.is_in_whitelist(safe_source):
                                    self.kill_process(pid)
                                    self.write_log("BLOCK", "Driver Block", pid=pid, source=safe_source, target=target, code=code, file_hash=self.calc_file_hash(safe_source))

                            else:
                                break
                        except OSError:
                            break

                    with self.lock_driver:
                        if self.driver_port:
                            self.kernel32.CloseHandle(self.driver_port)
                            self.driver_port = None

                time.sleep(0.1)
        except Exception as e:
            self.write_log("WARN", "pipe_server_thread", detail=str(e), success=False)


####################################################################################################

def get_base_path():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)

    return os.path.dirname(os.path.abspath(__file__))

class NoCacheRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.path.join(get_base_path(), "Interface"), **kwargs)

    def do_GET(self):
        if self.path == '/':
            self.path = '/templates/index.html'
        return super().do_GET()

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Expires", "0")
        self.send_header("Pragma", "no-cache")
        super().end_headers()

class WindowHook:
    def __init__(self, title, api_ref=None):
        self.title, self.api_ref = title, api_ref
        self.old_wndproc = None
        self.WM_DPICHANGED, self.WM_NCHITTEST, self.WM_COPYDATA, self.HTCAPTION, self.GWLP_WNDPROC = 0x02E0, 0x0084, 0x004A, 2, -4

        class RECT(ctypes.Structure):
            _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long), ("right", ctypes.c_long), ("bottom", ctypes.c_long)]

        self.RECT = RECT
        self.WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p)

        self.user32 = ctypes.windll.user32
        self.user32.FindWindowW.argtypes, self.user32.FindWindowW.restype = [ctypes.c_wchar_p, ctypes.c_wchar_p], ctypes.wintypes.HWND
        self.user32.CallWindowProcW.argtypes, self.user32.CallWindowProcW.restype = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_void_p

        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.SetWindowLong, self.GetWindowLong = self.user32.SetWindowLongPtrW, self.user32.GetWindowLongPtrW
        else:
            self.SetWindowLong, self.GetWindowLong = self.user32.SetWindowLongW, self.user32.GetWindowLongW

        self.SetWindowLong.argtypes, self.SetWindowLong.restype = [ctypes.c_void_p, ctypes.c_int, self.WNDPROC], ctypes.c_void_p
        self.GetWindowLong.argtypes, self.GetWindowLong.restype = [ctypes.c_void_p, ctypes.c_int], ctypes.c_void_p
        self.new_wndproc_cb = self.WNDPROC(self.wndproc)

    def hook(self):
        hwnd = self.user32.FindWindowW(None, self.title)
        if hwnd:
            self.old_wndproc = self.GetWindowLong(hwnd, self.GWLP_WNDPROC)
            self.SetWindowLong(hwnd, self.GWLP_WNDPROC, self.new_wndproc_cb)

            try:
                self.user32.ChangeWindowMessageFilterEx.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
                self.user32.ChangeWindowMessageFilterEx(hwnd, self.WM_COPYDATA, 1, None)

            except Exception:
                pass

    def wndproc(self, hwnd, msg, wparam, lparam):
        if msg in [0x0010, 0x0002, 0x0012, 0x0212] or (msg == 0x0112 and (wparam & 0xFFF0) == 0xF060):
            return 0

        if msg == self.WM_COPYDATA:
            try:
                cds = COPYDATASTRUCT.from_address(lparam)
                if cds.dwData == 1:
                    path = ctypes.string_at(cds.lpData, cds.cbData).decode('utf-8').strip('\x00')

                    if self.api_ref:
                        if self.api_ref._window:
                            self.api_ref._window.restore();
                            self.api_ref._window.show()

                        threading.Thread(target=self.api_ref.trigger_context_scan, args=(path,), daemon=True).start()

                elif cds.dwData == 2 and self.api_ref and self.api_ref._window:
                    self.api_ref._window.restore();
                    self.api_ref._window.show()

                elif cds.dwData == 3 and self.api_ref:
                    self.api_ref.close()

            except Exception:
                pass
            return 1

        if msg == self.WM_NCHITTEST:
            x, y = lparam & 0xFFFF, (lparam >> 16) & 0xFFFF
            if x >= 32768:
                x -= 65536
            if y >= 32768:
                y -= 65536

            rect = self.RECT()
            self.user32.GetWindowRect(hwnd, ctypes.byref(rect))
            if rect.top <= y <= rect.top + 44 and rect.left <= x <= rect.right - 150:
                return self.HTCAPTION

        if msg == self.WM_DPICHANGED:
            try:
                rect = self.RECT.from_address(lparam)
                self.user32.SetWindowPos(hwnd, None, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, 0x0004 | 0x0010 | 0x0020)

            except Exception:
                pass

        return self.user32.CallWindowProcW(self.old_wndproc, hwnd, msg, wparam, lparam) if self.old_wndproc else self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

####################################################################################################

def start_api(port_container, ready_event):
    TCPServer.allow_reuse_address = True
    try:
        with TCPServer(("127.0.0.1", 0), NoCacheRequestHandler) as httpd:
            port_container.append(httpd.server_address[1])
            ready_event.set()
            httpd.serve_forever()

    except Exception:
        ready_event.set()

if __name__ == "__main__":
    hide_on_start = "-h" in sys.argv or "-hide" in sys.argv
    init_width, init_height = 980, 670

    os.environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = "--proxy-bypass-list=127.0.0.1,localhost"

    port_container = []
    server_ready = threading.Event()
    api_thread = threading.Thread(target=start_api, args=(port_container, server_ready), daemon=True)
    api_thread.start()
    server_ready.wait(timeout=5.0)

    if not port_container:
        os._exit(1)

    js_api = WindowAPI()
    user32 = ctypes.windll.user32
    pos_x, pos_y = (user32.GetSystemMetrics(0) - init_width) // 2, (user32.GetSystemMetrics(1) - init_height) // 2

    window = webview.create_window(
        title="PYAS Security", url=f"http://127.0.0.1:{port_container[0]}/", width=init_width, height=init_height, x=pos_x, y=pos_y,
        frameless=True, easy_drag=False, js_api=js_api, background_color='#e0e0e0', hidden=hide_on_start)

    if platform.system() == "Windows":
        window_hook = WindowHook("PYAS Security", js_api)
        window.events.shown += window_hook.hook

    js_api.set_window(window)
    js_api.show_tray()

    def bind_dnd():
        try:
            window.dom.document.events.drop += DOMEventHandler(js_api.on_drop, True, True)
        except Exception:
            pass

    window.events.loaded += bind_dnd
    webview.start()
