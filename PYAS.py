import os, sys, time, copy, json, uuid, queue, platform, threading
import msvcrt, winreg, pystray, subprocess, webview, webbrowser
import ctypes, ctypes.wintypes

from concurrent.futures import ThreadPoolExecutor
from http.server import SimpleHTTPRequestHandler
from PIL import Image
from socketserver import TCPServer
from webview.dom import DOMEventHandler

from PYAS_Engine import sign_scanner, rule_scanner, pe_scanner, cloud_scanner
from PYAS_Protect import ProtectMixin
from PYAS_Scanner import ScannerMixin
from PYAS_Tools import COPYDATASTRUCT, FILE_NOTIFY_INFORMATION, FILTER_MESSAGE_HEADER, IO_COUNTERS, LUID, LUID_AND_ATTRIBUTES, MEMORY_BASIC_INFORMATION, MIB_TCPROW_OWNER_PID, POINT, PROCESSENTRY32W, PROCESS_BASIC_INFORMATION, PYAS_FULL_MESSAGE, PYAS_MESSAGE, PYAS_USER_MESSAGE, RECT, SERVICE_STATUS_PROCESS, SHQUERYRBINFO, TOKEN_PRIVILEGES, ToolsMixin, UNICODE_STRING

####################################################################################################

class _MainMixin:
    def __init__(self):
        self._window = None
        self.tray_icon = None
        self.logs_data = []
        self.logs_dirty = False

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

####################################################################################################

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
        self.path_rules = os.path.join(self.path_pyas, "Plugins", "Rules")
        self.path_drivers = os.path.join(self.path_protect, "PYAS_Driver.sys")

####################################################################################################

    def init_windll(self):
        for name in ["ntdll", "Psapi", "user32", "kernel32", "iphlpapi", "shell32", "fltlib", "advapi32"]:
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

        self.user32.WindowFromPoint.argtypes = [POINT]
        self.user32.WindowFromPoint.restype = ctypes.wintypes.HWND
        self.user32.GetAncestor.argtypes = [ctypes.wintypes.HWND, ctypes.c_uint]
        self.user32.GetAncestor.restype = ctypes.wintypes.HWND
        self.user32.GetCursorPos.argtypes = [ctypes.POINTER(POINT)]
        self.user32.GetCursorPos.restype = ctypes.wintypes.BOOL
        self.user32.GetWindowRect.argtypes = [ctypes.wintypes.HWND, ctypes.POINTER(RECT)]
        self.user32.GetWindowRect.restype = ctypes.wintypes.BOOL
        self.user32.SetWindowPos.argtypes = [ctypes.wintypes.HWND, ctypes.wintypes.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.wintypes.UINT]
        self.user32.SetWindowPos.restype = ctypes.wintypes.BOOL
        self.user32.SetLayeredWindowAttributes.argtypes = [ctypes.wintypes.HWND, ctypes.wintypes.DWORD, ctypes.c_byte, ctypes.wintypes.DWORD]
        self.user32.SetLayeredWindowAttributes.restype = ctypes.wintypes.BOOL
        self.user32.CreateWindowExW.restype = ctypes.wintypes.HWND

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
        self.fltlib.FilterUnload.argtypes = [ctypes.wintypes.LPCWSTR]
        self.fltlib.FilterUnload.restype = ctypes.c_long

        self.advapi32.OpenProcessToken.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.HANDLE)]
        self.advapi32.OpenProcessToken.restype = ctypes.wintypes.BOOL
        self.advapi32.LookupPrivilegeValueW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.POINTER(LUID)]
        self.advapi32.LookupPrivilegeValueW.restype = ctypes.wintypes.BOOL
        self.advapi32.AdjustTokenPrivileges.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.wintypes.DWORD, ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(ctypes.wintypes.DWORD)]
        self.advapi32.AdjustTokenPrivileges.restype = ctypes.wintypes.BOOL
        self.advapi32.OpenSCManagerW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD]
        self.advapi32.OpenSCManagerW.restype = ctypes.wintypes.HANDLE
        self.advapi32.CreateServiceW.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR]
        self.advapi32.CreateServiceW.restype = ctypes.wintypes.HANDLE
        self.advapi32.OpenServiceW.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD]
        self.advapi32.OpenServiceW.restype = ctypes.wintypes.HANDLE
        self.advapi32.ChangeServiceConfigW.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR]
        self.advapi32.ChangeServiceConfigW.restype = ctypes.wintypes.BOOL
        self.advapi32.StartServiceW.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.LPCWSTR)]
        self.advapi32.StartServiceW.restype = ctypes.wintypes.BOOL
        self.advapi32.QueryServiceStatusEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD)]
        self.advapi32.QueryServiceStatusEx.restype = ctypes.wintypes.BOOL
        self.advapi32.DeleteService.argtypes = [ctypes.wintypes.HANDLE]
        self.advapi32.DeleteService.restype = ctypes.wintypes.BOOL
        self.advapi32.CloseServiceHandle.argtypes = [ctypes.wintypes.HANDLE]
        self.advapi32.CloseServiceHandle.restype = ctypes.wintypes.BOOL

        self.kernel32.GetCurrentProcess.argtypes = []
        self.kernel32.GetCurrentProcess.restype = ctypes.wintypes.HANDLE
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
        self.kernel32.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.wintypes.BOOL, ctypes.wintypes.BOOL, ctypes.wintypes.LPCWSTR]
        self.kernel32.CreateEventW.restype = ctypes.wintypes.HANDLE
        self.kernel32.WaitForSingleObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD]
        self.kernel32.WaitForSingleObject.restype = ctypes.wintypes.DWORD
        self.kernel32.CancelIoEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p]
        self.kernel32.CancelIoEx.restype = ctypes.wintypes.BOOL
        self.kernel32.GetOverlappedResult.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.wintypes.BOOL]
        self.kernel32.GetOverlappedResult.restype = ctypes.wintypes.BOOL
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

####################################################################################################

    def init_variables(self):
        self.heuristic = rule_scanner()
        self.properties = pe_scanner()
        self.cloud = cloud_scanner()
        self.cloud_queue = queue.Queue()

        self.ui_queue = queue.Queue()
        self.start_daemon_thread(self.ui_dispatcher_thread)

        self.driver_port = None
        self.driver_stop_event = threading.Event()
        self.driver_listener_ready_event = threading.Event()
        self.driver_listener_failed_event = threading.Event()
        self.driver_listener_thread = None
        self.engine_initialized = False
        self.scan_running = False
        self.scan_finished = False
        self.virus_lock = {}
        self.virus_results = []
        self.scan_count = 0
        self.scan_events = {}
        self.hash_cache = {}
        self.mbr_backup = {}
        self.cloud_pending = set()
        self.last_io_counters = {}
        self.last_io_time = time.time()
        self.suspended_procs = set()

        self.lock_driver = threading.RLock()
        self.lock_driver_unload = threading.Lock()
        self.driver_unload_worker = None
        self.driver_unload_result = None
        self.lock_update = threading.RLock()
        self.lock_proc = threading.RLock()
        self.lock_net = threading.RLock()
        self.lock_io = threading.RLock()

        self.pyas_default = {
            "version": "3.6.2",
            "api_host": "https://pyas-security.com/",
            "api_key": "fBRZxYS1UxykM-qzNOlKOEl63WILzlvgNMn6QfsG6FXCAAIktCrOPTAfY5_hEyuZ",
            "suffix": [".exe", ".dll", ".sys", ".ocx", ".scr", ".efi", ".acm", ".ax", ".cpl", ".drv", ".com", ".mui", ".pyd", ".wfx", ".api", ".awx", ".rll", ".winmd"],
            "size": 256 * 1024 * 1024,
            "language": "english_switch",
            "theme": "system_switch",
            "first_launch": True,
            "process_switch": False,
            "suspend_switch": True,
            "load_switch": True,
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

####################################################################################################

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

####################################################################################################

    def _loc(self, text_dict):
        with self.lock_config:
            lang = self.pyas_config.get("language", "traditional_switch") if hasattr(self, 'pyas_config') else "traditional_switch"
        return text_dict.get(lang, text_dict.get("traditional_switch", ""))

    def load_config(self):
        with self.lock_config:

            if not os.path.exists(self.file_config):
                self.pyas_config = copy.deepcopy(self.pyas_default)
                self.write_log("INFO", "Config Update", detail="Create default config")
                self.save_config()

            else:
                try:
                    with open(self.file_config, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        self.pyas_config = copy.deepcopy(self.pyas_default)
                        self.pyas_config.update(data)

                    self.pyas_config["version"] = self.pyas_default["version"]
                except Exception as e:
                    self.pyas_config = copy.deepcopy(self.pyas_default)
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
            defer_driver_disable = key == "driver_switch" and not value

            with self.lock_config:
                old_value = self.pyas_config.get(key)
                if old_value == value:
                    return value

                if not defer_driver_disable:
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
                        if self.install_system_driver() and self.start_driver_listener(wait_ready=True):
                            success = True
                        else:
                            self.stop_system_driver()
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
                elif key == "autostart_switch":
                    self.manage_autostart(False)

                elif key == "document_switch":
                    with self.lock_file_ops:
                        if getattr(self, 'h_dir_file', None):
                            try:
                                self.kernel32.CloseHandle(self.h_dir_file)
                            except Exception:
                                pass
                            self.h_dir_file = None

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
                    if defer_driver_disable:
                        self.pyas_config[key] = value

                    self.write_log("INFO", "Config Update", detail=f"[{key}] {old_value} -> {value}")
                    self.save_config()

                if key == "language" and self.tray_icon:
                    try:
                        self.tray_icon.update_menu()
                    except Exception:
                        pass

                return value

            with self.lock_config:
                self.pyas_config[key] = old_value

            if self._window:
                self._window.evaluate_js(f"if(window.revertSwitch) window.revertSwitch('{key}');")

            return old_value

    def get_config(self):
        with self.lock_config:
            cfg = self.pyas_config.copy()

            rules = []
            if os.path.exists(self.path_rules):
                for f in os.listdir(self.path_rules):
                    if f.lower().endswith(".json"):
                        fp = os.path.join(self.path_rules, f)
                        rules.append({"file": fp, "time": os.path.getmtime(fp)})

            cfg["custom_rule"] = rules
            return cfg

    def reset_config(self):
        with self.lock_config:
            self.pyas_config = copy.deepcopy(self.pyas_default)
            self.write_log("INFO", "Config Update", detail="Reset to default")
            self.save_config()

        return True

    def load_logs(self):
        with self.lock_logs:
            pending_logs = list(self.logs_data)
            if os.path.exists(self.file_log):
                try:
                    with open(self.file_log, "r", encoding="utf-8") as f:
                        loaded_logs = json.load(f)

                    self.logs_data = (loaded_logs + pending_logs)[-1000:]
                except Exception:
                    self.logs_data = pending_logs

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

####################################################################################################

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
            self.logs_dirty = False

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

####################################################################################################

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

    def get_app_icon(self):
        icon_path = os.path.join(self.path_pyas, "Interface", "static", "img", "icon.ico")
        if os.path.exists(icon_path):
            try:
                return Image.open(icon_path)
            except Exception:
                pass

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

    def close(self, *args, **kwargs):
        with self.lock_config:
            driver_enabled = self.pyas_config.get("driver_switch", False)

        if driver_enabled and not self.stop_system_driver():
            self.write_log("WARN", "Driver Protection", detail="Controlled unload failed", success=False)
            if self._window:
                try:
                    self._window.show()
                except Exception:
                    pass
            return False

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
        os._exit(0)

    def init_ui_ready(self):
        with self.lock_config:
            if self.engine_initialized:
                return

            self.engine_initialized = True
        self.start_daemon_thread(self.init_engine_thread)

####################################################################################################

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

####################################################################################################

    def show_notification(self, title, message):
        try:
            if self.tray_icon:
                self.tray_icon.notify(message, title)

        except Exception as e:
            self.write_log("WARN", "show_notification", detail=str(e), success=False)

    def show_alert(self, title, message, style="info"):
        flags = 0x00000000 | (0x00000010 if style == "error" else 0x00000030 if style == "warning" else 0x00000040)
        self.user32.MessageBoxW(0, message, title, flags)
        return True

    def show_confirm(self, title, message):
        return self.user32.MessageBoxW(0, message, title, 0x00000004 | 0x00000020) == 6

####################################################################################################

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

####################################################################################################

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

    def select_files(self, file_types=None):
        if self._window: 
            kwargs = {"allow_multiple": True}
            if file_types:
                kwargs["file_types"] = tuple(file_types)

            return self._window.create_file_dialog(getattr(webview, 'OPEN_DIALOG', 10), **kwargs) or []
        return []

    def select_folder(self):
        if self._window: 
            return self._window.create_file_dialog(getattr(webview, 'FOLDER_DIALOG', 20)) or []
        return []

####################################################################################################

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

class WindowAPI(_MainMixin, ScannerMixin, ToolsMixin, ProtectMixin):
    pass


def get_base_path():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)

    return os.path.dirname(os.path.abspath(__file__))

####################################################################################################

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

####################################################################################################

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
