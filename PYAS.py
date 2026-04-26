import os, re, sys, time, json, uuid, stat, queue, msvcrt, winreg
import shutil, hashlib, platform, threading, subprocess, pefile, pystray
import socket, requests, webview, webbrowser, ctypes, ctypes.wintypes

from PIL import Image, ImageDraw
from concurrent.futures import ThreadPoolExecutor
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer

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

class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", ctypes.wintypes.DWORD),
        ("table", MIB_TCPROW_OWNER_PID * 1)
    ]

class FILE_NOTIFY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset", ctypes.wintypes.DWORD),
        ("Action", ctypes.wintypes.DWORD),
        ("FileNameLength", ctypes.wintypes.DWORD),
        ("FileName", ctypes.wintypes.WCHAR * 1024)
    ]

class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", ctypes.wintypes.DWORD),
        ("dwCurrentState", ctypes.wintypes.DWORD),
        ("dwControlsAccepted", ctypes.wintypes.DWORD),
        ("dwWin32ExitCode", ctypes.wintypes.DWORD),
        ("dwServiceSpecificExitCode", ctypes.wintypes.DWORD),
        ("dwCheckPoint", ctypes.wintypes.DWORD),
        ("dwWaitHint", ctypes.wintypes.DWORD)
    ]

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.wintypes.LPVOID),
        ("PebBaseAddress", ctypes.wintypes.LPVOID),
        ("Reserved2", ctypes.wintypes.LPVOID * 2),
        ("UniqueProcessId", ctypes.wintypes.LPVOID),
        ("Reserved3", ctypes.wintypes.LPVOID)
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
                if "-scan" in self.args_pyas:
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
                    except Exception:
                        pass
                else:
                    try:
                        cds = COPYDATASTRUCT()
                        cds.dwData = 2
                        cds.cbData = 0
                        cds.lpData = None
                        self.user32.SendMessageTimeoutW(hwnd, 0x004A, 0, ctypes.byref(cds), 0x0002, 3000, None)
                    except Exception:
                        pass
                self.user32.SetForegroundWindow(hwnd)
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

    def init_ui_ready(self):
        with self.lock_config:
            if self.engine_initialized:
                return
            self.engine_initialized = True

        self.start_daemon_thread(self.init_engine_thread)

    def set_window(self, window):
        self._window = window

    def minimize(self):
        hwnd = self.user32.FindWindowW(None, "PYAS Security")
        if hwnd:
            self.user32.ShowWindow(hwnd, 6)
        elif self._window:
            self._window.minimize()

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
        with self.lock_config:
            lang = self.pyas_config.get("language", "traditional_switch")

        texts = {
            "open_ui": {
                "traditional_switch": "開啟介面",
                "simplified_switch": "打开界面",
                "english_switch": "Open PYAS",
                "japanese_switch": "PYAS を開く",
                "korean_switch": "PYAS 열기",
                "french_switch": "Ouvrir PYAS",
                "spanish_switch": "Abrir PYAS",
                "hindi_switch": "PYAS खोलें",
                "arabic_switch": "فتح PYAS",
                "russian_switch": "Открыть PYAS",
                "slovenian_switch": "Odpri PYAS"
            },
            "exit_app": {
                "traditional_switch": "退出防護",
                "simplified_switch": "退出防护",
                "english_switch": "Exit Security",
                "japanese_switch": "保護を終了",
                "korean_switch": "보호 종료",
                "french_switch": "Quitter la sécurité",
                "spanish_switch": "Salir de la seguridad",
                "hindi_switch": "सुरक्षा से बाहर निकलें",
                "arabic_switch": "خروج من الحماية",
                "russian_switch": "Выйти из защиты",
                "slovenian_switch": "Izhod iz zaščite"
            }
        }
        return texts.get(key, {}).get(lang, texts[key]["traditional_switch"])

    def show_tray(self):
        if self.tray_icon is not None:
            return

        menu = pystray.Menu(
            pystray.MenuItem(lambda item: self.get_tray_text("open_ui"), self.restore_from_tray, default=True),
            pystray.MenuItem(lambda item: self.get_tray_text("exit_app"), self.close)
        )
        self.tray_icon = pystray.Icon("PYAS", self.get_app_icon(), "PYAS Security", menu)
        self.tray_icon.run_detached()

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

        def _cleanup_and_exit():
            with self.lock_config:
                self.pyas_config["process_switch"] = False
                self.pyas_config["document_switch"] = False
                self.pyas_config["system_switch"] = False
                self.pyas_config["driver_switch"] = False
                self.pyas_config["network_switch"] = False

            self.stop_system_driver()
            
            if self._window:
                self._window.destroy()
            os._exit(0)

        threading.Thread(target=_cleanup_and_exit, daemon=True).start()

    def get_file_version(self, file_path):
        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            if hasattr(pe, 'FileInfo'):
                for fileinfo_list in pe.FileInfo:
                    for info in fileinfo_list:
                        if getattr(info, 'name', '') in ('StringFileInfo', b'StringFileInfo'):
                            for st in getattr(info, 'StringTable', []):
                                for key, val in st.entries.items():
                                    k = key.decode('utf-8', 'ignore') if isinstance(key, bytes) else str(key)
                                    v = val.decode('utf-8', 'ignore') if isinstance(val, bytes) else str(val)
                                    if k == 'FileVersion':
                                        pe.close()
                                        return v.strip()
            pe.close()
        except Exception:
            pass
        return "0.0.0.0"

    def compare_versions(self, v1, v2):
        try:
            t1 = tuple(int(x) for x in re.findall(r"\d+", v1))
            t2 = tuple(int(x) for x in re.findall(r"\d+", v2))
            return t1 >= t2
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
        self.path_pattern = os.path.join(self.path_pyas, "Engine", "Pattern")
        self.path_heuristic = os.path.join(self.path_pyas, "Engine", "Heuristic")
        self.path_protect = os.path.join(self.path_pyas, "Plugins", "Filter")
        self.path_drivers = os.path.join(self.path_protect, "PYAS_Driver.sys")

####################################################################################################

    def init_windll(self):
        for name in ["ntdll", "Psapi", "user32", "kernel32", "advapi32", "iphlpapi", "shell32", "fltlib"]:
            try:
                setattr(self, name.lower(), ctypes.WinDLL(name, use_last_error=True))
            except Exception as e:
                self.write_log("WARN", "init_windll", detail=str(e), success=False)

        self.advapi32.OpenSCManagerW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.wintypes.DWORD]
        self.advapi32.OpenSCManagerW.restype = ctypes.wintypes.HANDLE
        self.advapi32.CreateServiceW.argtypes = [
            ctypes.wintypes.HANDLE, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.c_wchar_p,
            ctypes.c_wchar_p, ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.c_wchar_p, ctypes.c_wchar_p,
            ctypes.c_wchar_p]
        self.advapi32.CreateServiceW.restype = ctypes.wintypes.HANDLE
        self.advapi32.OpenServiceW.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_wchar_p, ctypes.wintypes.DWORD]
        self.advapi32.OpenServiceW.restype = ctypes.wintypes.HANDLE
        self.advapi32.StartServiceW.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.c_wchar_p)]
        self.advapi32.StartServiceW.restype = ctypes.wintypes.BOOL
        self.advapi32.ControlService.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.POINTER(SERVICE_STATUS)]
        self.advapi32.ControlService.restype = ctypes.wintypes.BOOL
        self.advapi32.DeleteService.argtypes = [ctypes.wintypes.HANDLE]
        self.advapi32.DeleteService.restype = ctypes.wintypes.BOOL
        self.advapi32.CloseServiceHandle.argtypes = [ctypes.wintypes.HANDLE]
        self.advapi32.CloseServiceHandle.restype = ctypes.wintypes.BOOL

        self.ntdll.NtQueryInformationProcess.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.ULONG, ctypes.c_void_p, ctypes.wintypes.ULONG, ctypes.POINTER(ctypes.wintypes.ULONG)]
        self.ntdll.NtQueryInformationProcess.restype = ctypes.wintypes.ULONG
        self.ntdll.NtSuspendProcess.argtypes = [ctypes.wintypes.HANDLE]
        self.ntdll.NtSuspendProcess.restype = ctypes.c_ulong
        self.ntdll.NtResumeProcess.argtypes = [ctypes.wintypes.HANDLE]
        self.ntdll.NtResumeProcess.restype = ctypes.c_ulong

        self.shell32.CommandLineToArgvW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
        self.shell32.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.wintypes.LPWSTR)

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

####################################################################################################

    def init_variables(self):
        self.python = sys.executable
        self.sign = sign_scanner()
        self.sign.init_windll(["wintrust"])
        self.heuristic = rule_scanner()
        self.properties = pe_scanner()
        self.cloud = cloud_scanner()
        self.cloud_queue = queue.Queue()
        
        self.lock_driver = threading.RLock()
        self.driver_port = None
        self.scan_running = False
        self.scan_finished = False
        self.virus_lock = {}
        self.virus_results = []
        self.scan_count = 0
        self.mbr_backup = {}
        self.logs_data = []
        self.tray_icon = None
        self.engine_initialized = False

        self.lock_proc = threading.RLock()
        self.lock_net = threading.RLock()

        self.pyas_default = {
            "version": "3.5.1",
            "api_host": "https://pyas-security.com/",
            "api_key": "fBRZxYS1UxykM-qzNOlKOEl63WILzlvgNMn6QfsG6FXCAAIktCrOPTAfY5_hEyuZ",
            "suffix": [".exe", ".dll", ".sys", ".ocx", ".scr", ".efi", ".acm", ".ax", ".cpl", ".drv", ".com", ".mui", ".pyd"],
            "block": [2001, 3001, 5001, 6001],
            "size": 100 * 1024 * 1024,
            "language": "english_switch",
            "theme": "white_switch",
            "process_switch": True,
            "document_switch": True,
            "system_switch": True,
            "driver_switch": True,
            "network_switch": True,
            "extension_switch": False,
            "sensitive_switch": False,
            "cloud_switch": True,
            "context_switch": False,
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

        self.thread_pool = ThreadPoolExecutor(max_workers=8)
        for _ in range(2):
            self.start_daemon_thread(self.cloud_worker)

####################################################################################################

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
        with self.lock_config:
            old_value = self.pyas_config.get(key)
            if old_value != value:
                self.pyas_config[key] = value
                self.write_log("INFO", "Config Update", detail=f"[{key}] {old_value} -> {value}")
                self.save_config()
            
        if key == "process_switch" and value:
            self.start_daemon_thread(self.protect_proc_thread)
        elif key == "document_switch" and value:
            self.start_daemon_thread(self.protect_file_thread)
        elif key == "system_switch" and value:
            self.start_daemon_thread(self.protect_system_thread)
        elif key == "network_switch" and value:
            self.start_daemon_thread(self.protect_net_thread)
        elif key == "context_switch":
            self.register_context_menu(value)
        elif key == "driver_switch":
            if value:
                if self.install_system_driver():
                    self.start_daemon_thread(self.pipe_server_thread)
                else:
                    with self.lock_config:
                        self.pyas_config[key] = False
                        self.write_log("INFO", "Config Update", detail=f"[{key}] True -> False")
                        self.save_config()
                    if self._window:
                        self._window.evaluate_js(f"if(window.revertSwitch) window.revertSwitch('{key}');")
            else:
                self.stop_system_driver()

    def get_config(self):
        with self.lock_config:
            return self.pyas_config.copy()

####################################################################################################

    def register_context_menu(self, enable):
        paths = [
            r"Software\Classes\*\shell\PYAS_Scan",
            r"Software\Classes\Directory\shell\PYAS_Scan"
        ]
        
        if getattr(sys, 'frozen', False):
            cmd_path = f'"{self.file_pyas}"'
        else:
            cmd_path = f'"{self.python}" "{self.file_pyas}"'
            
        try:
            for path in paths:
                if enable:
                    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
                        winreg.SetValue(key, "", winreg.REG_SZ, "PYAS Security Scan")
                        winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, f'{cmd_path},0')
                    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"{path}\command") as key:
                        winreg.SetValue(key, "", winreg.REG_SZ, f'{cmd_path} -scan "%1"')
                else:
                    try:
                        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, rf"{path}\command")
                        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
                    except FileNotFoundError:
                        pass
        except Exception as e:
            self.write_log("WARN", "register_context_menu", detail=str(e), success=False)

    def trigger_context_scan(self, target):
        if self._window:
            self._window.evaluate_js(f"if(window.triggerContextScan) window.triggerContextScan({json.dumps(target.replace(os.sep, '/'))});")

####################################################################################################

    def show_notification(self, title, message):
        try:
            if self.tray_icon:
                self.tray_icon.notify(message, title)
        except Exception as e:
            self.write_log("WARN", "show_notification", detail=str(e), success=False)

####################################################################################################

    def load_logs(self):
        with self.lock_logs:
            if os.path.exists(self.file_log):
                try:
                    with open(self.file_log, "r", encoding="utf-8") as f:
                        self.logs_data = json.load(f)

                except Exception:
                    self.logs_data = []

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
            if len(self.logs_data) > 10000:
                self.logs_data = self.logs_data[-10000:]

            try:
                os.makedirs(os.path.dirname(self.file_log), exist_ok=True)
                with open(self.file_log, "w", encoding="utf-8") as f:
                    json.dump(self.logs_data, f, indent=4, ensure_ascii=False)
            except Exception:
                pass

            if self._window:
                self._window.evaluate_js(f"if(window.updateLogs) window.updateLogs({json.dumps(entry)});")

        if level == "BLOCK" and self.tray_icon:
            self.trigger_block_notification(action, source, target, code)

    def trigger_block_notification(self, action, source, target, code):
        if action not in ["Process Block", "File Block", "Network Block", "Driver Block"]:
            return

        with self.lock_config:
            lang = self.pyas_config.get("language", "traditional_switch")

        path = source or ""

        titles = {
            "Process Block": {
                "traditional_switch": "進程防護", "simplified_switch": "进程防护", "english_switch": "Process Protection",
                "japanese_switch": "プロセス保護", "korean_switch": "프로세스 보호", "french_switch": "Protection des Processus",
                "spanish_switch": "Protección de Procesos", "hindi_switch": "प्रक्रिया सुरक्षा", "arabic_switch": "حماية العمليات",
                "russian_switch": "Защита процессов", "slovenian_switch": "Zaščita procesov"
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

        messages = {
            "traditional_switch": f"威脅已終止: {path}",
            "simplified_switch": f"威胁已终止: {path}",
            "english_switch": f"Threat terminated: {path}",
            "japanese_switch": f"脅威が終了しました: {path}",
            "korean_switch": f"위협이 종료되었습니다: {path}",
            "french_switch": f"Menace terminée : {path}",
            "spanish_switch": f"Amenaza terminada: {path}",
            "hindi_switch": f"खतरा समाप्त: {path}",
            "arabic_switch": f"تم إنهاء التهديد: {path}",
            "russian_switch": f"Угроза устранена: {path}",
            "slovenian_switch": f"Grožnja odpravljena: {path}"
        }

        title = titles.get(action, {}).get(lang, titles.get(action, {})["traditional_switch"])
        message = messages.get(lang, messages["traditional_switch"])
        
        try:
            self.tray_icon.notify(message, title)
        except Exception:
            pass

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

####################################################################################################

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
                hr = self.fltlib.FilterSendMessage(self.driver_port, ctypes.byref(msg), ctypes.sizeof(msg), None, 0, ctypes.byref(bytes_returned))
                return hr == 0
            except Exception:
                return False

    def show_alert(self, title, message, style="info"):
        MB_OK = 0x00000000
        MB_ICONINFORMATION = 0x00000040
        MB_ICONWARNING = 0x00000030
        MB_ICONERROR = 0x00000010

        flags = MB_OK
        if style == "error":
            flags |= MB_ICONERROR
        elif style == "warning":
            flags |= MB_ICONWARNING
        else:
            flags |= MB_ICONINFORMATION

        self.user32.MessageBoxW(0, message, title, flags)
        return True

    def show_confirm(self, title, message):
        MB_YESNO = 0x00000004
        MB_ICONQUESTION = 0x00000020
        IDYES = 6
        return self.user32.MessageBoxW(0, message, title, MB_YESNO | MB_ICONQUESTION) == IDYES

    def prompt_virus_action(self, path):
        with self.lock_config:
            lang = self.pyas_config.get("language", "traditional_switch")
            
        messages = {
            "traditional_switch": (f"對 {path} 執行動作:\n\n[是] 加入白名單\n[否] 加入隔離區\n[取消] 不做任何事", "操作選擇"),
            "simplified_switch": (f"对 {path} 执行动作:\n\n[是] 加入白名单\n[否] 加入隔离区\n[取消] 不做任何事", "操作选择"),
            "english_switch": (f"Action for {path}:\n\n[Yes] Add to Whitelist\n[No] Add to Quarantine\n[Cancel] Do nothing", "Operation Selection"),
            "japanese_switch": (f"{path} に対するアクション:\n\n[はい] ホワイトリストに追加\n[いいえ] 隔離に追加\n[キャンセル] 何もしない", "操作の選択"),
            "korean_switch": (f"{path}에 대한 작업:\n\n[예] 화이트리스트에 추가\n[아니요] 격리소에 추가\n[취소] 아무 작업도 하지 않음", "작업 선택"),
            "french_switch": (f"Action pour {path} :\n\n[Oui] Ajouter à la liste blanche\n[Non] Ajouter à la quarantaine\n[Annuler] Ne rien faire", "Sélection d'opération"),
            "spanish_switch": (f"Acción para {path}:\n\n[Sí] Añadir a la lista blanca\n[No] Añadir a la cuarentena\n[Cancelar] No hacer nada", "Selección de operación"),
            "hindi_switch": (f"{path} के लिए कार्रवाई:\n\n[हाँ] श्वेतसूची में जोड़ें\n[नहीं] संगरोध में जोड़ें\n[रद्द करें] कुछ न करें", "ऑपरेशन चयन"),
            "arabic_switch": (f"إجراء لـ {path}:\n\n[نعم] إضافة إلى القائمة البيضاء\n[لا] إضافة إلى الحجر الصحي\n[إلغاء] لا تفعل شيئًا", "تحديد العملية"),
            "russian_switch": (f"Действие для {path}:\n\n[Да] Добавить в белый список\n[Нет] Добавить в карантин\n[Отмена] Ничего не делать", "Выбор операции"),
            "slovenian_switch": (f"Dejanje za {path}:\n\n[Da] Dodaj na seznam dovoljenih\n[Ne] Dodaj v karanteno\n[Prekliči] Ne naredi ničesar", "Izbira operacije")
        }
        
        msg, title = messages.get(lang, messages["traditional_switch"])

        MB_YESNOCANCEL = 0x00000003
        MB_ICONQUESTION = 0x00000020
        IDYES = 6
        IDNO = 7

        res = self.user32.MessageBoxW(0, msg, title, MB_YESNOCANCEL | MB_ICONQUESTION)
        if res == IDYES:
            return "1"
        elif res == IDNO:
            return "2"
        return "0"

####################################################################################################

    def start_daemon_thread(self, target, *args, **kwargs):
        t = threading.Thread(target=target, args=args, kwargs=kwargs, daemon=True)
        t.start()
        return t

    def init_engine_thread(self):
        try:
            self.backup_mbr()
            self.relock_file()
            self.init_whitelist()
            self.start_daemon_thread(self.popup_intercept_thread)
            
            def log_callback(x):
                self.write_log("INFO", "Load Engine", source=os.path.basename(x))
                
            self.heuristic.load_path(self.path_heuristic, callback=log_callback)
            self.properties.load_path(self.path_properties, callback=log_callback)
            self.write_log("INFO", "System", detail="Engine Initialization Complete")
            
            if "-scan" in self.args_pyas:
                try:
                    idx = self.args_pyas.index("-scan")
                    target = self.args_pyas[idx+1]
                    self.trigger_context_scan(target)
                except Exception:
                    pass
            
            with self.lock_config:
                if self.pyas_config.get("process_switch"): self.start_daemon_thread(self.protect_proc_thread)
                if self.pyas_config.get("document_switch"): self.start_daemon_thread(self.protect_file_thread)
                if self.pyas_config.get("system_switch"): self.start_daemon_thread(self.protect_system_thread)
                if self.pyas_config.get("network_switch"): self.start_daemon_thread(self.protect_net_thread)
                if self.pyas_config.get("driver_switch"):
                    if self.install_system_driver():
                        self.start_daemon_thread(self.pipe_server_thread)
                    else:
                        self.update_config("driver_switch", False)

        except Exception as e:
            self.write_log("WARN", "init_engine_thread", detail=str(e), success=False)

    def backup_mbr(self, max_drives=26):
        self.mbr_backup = {}
        mbr_signature = b"\x55\xAA"
        for drive in range(max_drives):
            drive_path = rf"\\.\PhysicalDrive{drive}"
            try:
                with open(drive_path, "rb") as f:
                    mbr = f.read(512)
                    if len(mbr) == 512 and mbr[510:512] == mbr_signature:
                        self.mbr_backup[drive] = mbr

            except Exception:
                continue

    def norm_path(self, path, must_exist=True):
        if isinstance(path, list):
            return [p for p in (self.norm_path(x, must_exist) for x in path) if p]

        if isinstance(path, str):
            ap = os.path.normpath(os.path.abspath(path))
            return ap if (not must_exist or os.path.exists(ap)) else None

        return path

    def path_equal(self, a, b):
        pa = self.norm_path(a, must_exist=False)
        pb = self.norm_path(b, must_exist=False)
        if not pa or not pb:
            return False

        return os.path.normcase(pa) == os.path.normcase(pb)

    def start_scan(self, targets):
        with self.lock_virus:
            self.scan_running = True
            self.scan_finished = False
            self.virus_results = []
            self.scan_count = 0
            self.scan_start = time.time()

        self.thread_pool.submit(self.scan_worker, targets)

    def stop_scan(self):
        with self.lock_virus:
            self.scan_running = False

####################################################################################################

    def scan_worker(self, targets):
        try:
            for file_path in self.yield_files(targets):
                with self.lock_virus:
                    if not self.scan_running:
                        break
                
                norm_path = self.norm_path(file_path)
                if not norm_path:
                    continue

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
                        suffix = self.pyas_config.get("suffix", [])
                        
                    ext = os.path.splitext(norm_path)[-1].lower()
                    if ext not in suffix:
                        continue

                    result = self.scan_engine(norm_path)
                    if result:
                        with self.lock_virus:
                            self.virus_results.append(norm_path)
                        if self._window:
                            self._window.evaluate_js(f"if(window.addVirusResult) window.addVirusResult({json.dumps(result)}, {json.dumps(norm_path.replace(os.sep, '/'))});")
                        self.cloud_check(norm_path)
                        self.write_log("SCAN", "Virus Detected", source=norm_path, file_hash=self.calc_file_hash(norm_path))

                    if self._window:
                        self._window.evaluate_js(f"if(window.updateScanProgress) window.updateScanProgress({json.dumps(norm_path.replace(os.sep, '/'))});")

                except Exception as e:
                    self.write_log("WARN", "Scan Engine", source=norm_path, detail=str(e), success=False)
                finally:
                    if was_locked:
                        self.lock_file(norm_path, True)
        finally:
            with self.lock_virus:
                self.scan_finished = True
                count = len(self.virus_results)
                elapsed = int(time.time() - self.scan_start)
                scanned = self.scan_count
            
            with self.lock_config:
                lang = self.pyas_config.get("language", "traditional_switch")

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
            result_msg = messages.get(lang, messages["traditional_switch"])

            if self._window:
                self._window.evaluate_js(f"if(window.finishScan) window.finishScan({json.dumps(result_msg)}, {count});")
            self.write_log("INFO", "Scan Completed", detail=f"Found {count} viruses, scanned {scanned} files, time {elapsed}s")

####################################################################################################

    def yield_files(self, targets):
        if isinstance(targets, str):
            if os.path.isdir(targets):
                for root, _, files in os.walk(targets):
                    for f in files:
                        yield self.norm_path(os.path.join(root, f))
            elif os.path.isfile(targets):
                yield self.norm_path(targets)

        elif isinstance(targets, (list, tuple, set)):
            for t in targets:
                yield from self.yield_files(t)

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

####################################################################################################

    def solve_scan(self, file_paths):
        deleted_paths = []
        running_procs = self.get_process_list()
        
        with self.lock_virus:
            for raw_path in file_paths:
                path = self.norm_path(raw_path, must_exist=False)
                if not path:
                    continue

                if self._window:
                    self._window.evaluate_js(f"if(window.updateDeleteProgress) window.updateDeleteProgress({json.dumps(path.replace(os.sep, '/'))});")
                    
                try:
                    if path in self.virus_lock:
                        self.lock_file(path, False)

                    for proc in running_procs:
                        if self.path_equal(proc["path"], path):
                            self.kill_process(proc["pid"])

                    try:
                        os.chmod(path, stat.S_IWRITE)
                    except Exception:
                        pass

                    self.remove_list_items("quarantine", [path])
                    os.remove(path)
                    deleted_paths.append(raw_path) 
                    
                    if path in self.virus_results:
                        self.virus_results.remove(path)

                    self.write_log("INFO", "Virus Delete", source=path, file_hash=self.calc_file_hash(path), operate=True, success=True)

                except Exception as e:
                    self.write_log("SCAN", "Virus Delete", source=path, file_hash=self.calc_file_hash(path), detail=str(e), operate=True, success=False)

            remaining = len(self.virus_results)
        
        with self.lock_config:
            lang = self.pyas_config.get("language", "traditional_switch")

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
        result_msg = messages.get(lang, messages["traditional_switch"])

        if self._window:
            self._window.evaluate_js(f"if(window.finishScan) window.finishScan({json.dumps(result_msg)}, {remaining});")
        return deleted_paths

####################################################################################################

    def trigger_scan(self, method):
        with self.lock_config:
            lang = self.pyas_config.get("language", "traditional_switch")
            
        messages = {
            "traditional_switch": "已取消掃描",
            "simplified_switch": "已取消扫描",
            "english_switch": "Scan cancelled",
            "japanese_switch": "スキャンがキャンセルされました",
            "korean_switch": "스캔이 취소되었습니다",
            "french_switch": "Analyse annulée",
            "spanish_switch": "Escaneo cancelado",
            "hindi_switch": "स्कैन रद्द कर दिया गया",
            "arabic_switch": "تم إلغاء الفحص",
            "russian_switch": "Сканирование отменено",
            "slovenian_switch": "Skeniranje preklicano"
        }
        cancel_msg = messages.get(lang, messages["traditional_switch"])

        targets = []
        if method == "smart":
            for folder in ["Desktop", "Downloads", "AppData"]:
                fp = os.path.join(self.path_user, folder)
                if os.path.exists(fp):
                    targets.append(fp)
                
            if os.path.exists(self.path_config):
                targets.append(self.path_config)
                
            for proc in self.get_process_list():
                if proc["path"] and proc["path"] != "None":
                    targets.append(proc["path"])
            self.start_scan(list(set(targets)))

        elif method == "file":
            targets = self.select_files()
            if targets: 
                self.start_scan(targets)
            else:
                if self._window:
                    self._window.evaluate_js(f"if(window.finishScan) window.finishScan('{cancel_msg}', 0);")

        elif method == "path":
            targets = self.select_folder()
            if targets: 
                self.start_scan(targets)
            else:
                if self._window:
                    self._window.evaluate_js(f"if(window.finishScan) window.finishScan('{cancel_msg}', 0);")

        elif method == "full":
            targets = [f"{chr(d)}:/" for d in range(65, 91) if os.path.exists(f"{chr(d)}:/")]
            self.start_scan(targets)

####################################################################################################

    def open_file_location(self, file_path):
        if file_path and os.path.exists(file_path):
            try:
                subprocess.Popen(f'explorer /select,"{file_path}"')
                return True
            except Exception:
                pass
        return False

####################################################################################################

    def cloud_worker(self):
        while True:
            try:
                file_path = self.cloud_queue.get()
                self.perform_cloud_scan(file_path)
                self.cloud_queue.task_done()
            except Exception:
                pass

    def cloud_check(self, file_path):
        self.cloud_queue.put(file_path)

    def perform_cloud_scan(self, file_path):
        was_locked = False
        try:
            with self.lock_config:
                if not self.pyas_config.get("cloud_switch", True):
                    return False
                api_host = self.pyas_config.get("api_host")
                api_key = self.pyas_config.get("api_key")
                max_size = self.pyas_config.get("size", 100 * 1024 * 1024)

            if not os.path.exists(file_path) or not os.path.isfile(file_path): 
                return False

            with self.lock_file_ops:
                if file_path in self.virus_lock:
                    self.lock_file(file_path, False)
                    was_locked = True

            size = os.path.getsize(file_path)
            if size > max_size:
                if was_locked:
                    self.lock_file(file_path, True)
                return False

            success, sha256 = self.cloud.upload_file(file_path, api_host, api_key)
            
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

    def scan_system_junk(self):
        junk_list = []
        try:
            for path in [self.path_temp, self.path_systemp]:
                if os.path.exists(path):
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            full_path = os.path.join(root, file)
                            try:
                                size = os.path.getsize(full_path)
                                junk_list.append({"path": full_path, "size": size})
                            except Exception:
                                pass
            return junk_list

        except Exception as e:
            self.write_log("WARN", "scan_system_junk", detail=str(e), success=False)
            return []

    def clean_system_junk(self, paths_to_delete=None):
        total_deleted = 0
        try:
            if paths_to_delete is not None:
                for path in paths_to_delete:
                    try:
                        size = os.path.getsize(path)
                        os.remove(path)
                        total_deleted += size
                    except Exception:
                        pass
            else:
                for path in [self.path_temp, self.path_systemp]:
                    total_deleted += self._traverse_delete(path)
            
            self.write_log("INFO", "Clean Junk", detail=f"Deleted {total_deleted // 1024} KB", operate=True)
            return total_deleted

        except Exception as e:
            self.write_log("WARN", "clean_system_junk", detail=str(e), operate=True, success=False)
            return 0

    def remove_list_items(self, list_key, paths_to_remove):
        with self.lock_config:
            target_list = self.pyas_config.get(list_key, [])
            original_len = len(target_list)
            
            if list_key == "quarantine":
                for item in target_list:
                    if isinstance(item, dict) and item.get("file") in paths_to_remove:
                        self.lock_file(item["file"], False)
            
            new_list = []
            removed_items = []
            for item in target_list:
                if isinstance(item, dict):
                    val = item.get("file") or item.get("exe") or item.get("title")
                    if val not in paths_to_remove:
                        new_list.append(item)
                    else:
                        removed_items.append(val)
                        if list_key == "white_list":
                            self.sync_driver_whitelist(val, False)
                else:
                    if item not in paths_to_remove:
                        new_list.append(item)
                    else:
                        removed_items.append(item)
                        if list_key == "white_list":
                            self.sync_driver_whitelist(item, False)
            
            self.pyas_config[list_key] = new_list
            
            if len(self.pyas_config[list_key]) < original_len:
                self.write_log("INFO", "Config Update", detail=f"List [{list_key}] remove: {removed_items}")
                self.save_config()
                return True
        return False

    def _traverse_delete(self, path):
        deleted = 0
        if not os.path.exists(path):
            return deleted

        for fd in os.listdir(path):
            file = os.path.join(path, fd)
            try:
                if os.path.isdir(file):
                    deleted += self._traverse_delete(file)
                    try:
                        os.rmdir(file)
                    except Exception:
                        pass
                else:
                    size = os.path.getsize(file)
                    os.remove(file)
                    deleted += size
            except Exception:
                continue
        return deleted

####################################################################################################

    def scan_system_repair(self):
        items = []

        if self.check_system_mbr():
            items.append({"display": "修復系統 MBR", "value": "mbr"})
        if self.check_system_restrict():
            items.append({"display": "修復系統限制", "value": "restrict"})
        if self.check_system_file_type():
            items.append({"display": "修復檔案關聯", "value": "file_type"})
        if self.check_system_file_icon():
            items.append({"display": "修復檔案圖標", "value": "file_icon"})
        if self.check_system_image():
            items.append({"display": "修復映像劫持", "value": "image"})
        if self.check_system_wallpaper():
            items.append({"display": "修復桌面壁紙", "value": "wallpaper"})

        return items

    def check_system_mbr(self):
        if not self.mbr_backup:
            return False

        for drive, mbr_value in self.mbr_backup.items():
            drive_path = rf"\\.\PhysicalDrive{drive}"
            try:
                with open(drive_path, "rb") as f:
                    if f.read(512) != mbr_value:
                        return True

            except Exception:
                pass
        return False

    def _get_restrict_lists(self):
        permissions = [
            "NoControlPanel", "NoDrives", "NoFileMenu", "NoFind", "NoStartMenuPinnedList",
            "NoSetFolders", "NoSetFolderOptions", "NoViewOnDrive", "NoClose", "NoDesktop",
            "NoLogoff", "NoFolderOptions", "RestrictRun", "NoViewContextMenu", "HideClock",
            "NoStartMenuMyGames", "NoStartMenuMyMusic", "DisableCMD", "NoAddingComponents",
            "NoWinKeys", "NoStartMenuLogOff", "NoSimpleNetIDList", "NoLowDiskSpaceChecks",
            "DisableLockWorkstation","Restrict_Run", "DisableTaskMgr", "DisableRegistryTools",
            "DisableChangePassword", "Wallpaper", "NoComponents", "NoStartMenuMorePrograms",
            "NoActiveDesktop", "NoSetActiveDesktop", "NoRecentDocsMenu", "NoWindowsUpdate",
            "NoChangeStartMenu", "NoFavoritesMenu", "NoRecentDocsHistory", "NoSetTaskbar",
            "NoSMHelp", "NoTrayContextMenu", "NoManageMyComputerVerb", "NoRealMode", "NoRun",
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
        permissions, restrict_paths = self._get_restrict_lists()
        for hkey, path in restrict_paths:
            try:
                with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ) as reg:
                    for val in permissions:
                        try:
                            winreg.QueryValueEx(reg, val)
                            return True
                        except FileNotFoundError:
                            pass
            except Exception:
                pass
        return False

    def check_system_file_type(self):
        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for ext in [".exe", ".bat", ".cmd", ".com"]:
                try:
                    with winreg.OpenKey(root, rf"SOFTWARE\Classes\{ext}", 0, winreg.KEY_READ) as reg:
                        val, _ = winreg.QueryValueEx(reg, "")
                        if val != ("exefile" if ext == ".exe" else ext[1:]+"file"): 
                            return True
                except Exception:
                    pass
            for shell_cmd in ["open", "runas"]:
                try:
                    with winreg.OpenKey(root, rf"SOFTWARE\Classes\exefile\shell\{shell_cmd}\command", 0, winreg.KEY_READ) as reg:
                        val, _ = winreg.QueryValueEx(reg, "")
                        if val != '"%1" %*': 
                            return True
                except Exception:
                    pass
        return False

    def check_system_file_icon(self):
        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            try:
                with winreg.OpenKey(root, r"SOFTWARE\Classes\exefile\DefaultIcon", 0, winreg.KEY_READ) as reg:
                    val, _ = winreg.QueryValueEx(reg, "")
                    if val != "%1":
                        return True
            except Exception:
                pass
        return False

    def check_system_image(self):
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as reg:
                i = 0
                while True:
                    try:
                        subkey = winreg.EnumKey(reg, i)
                        with winreg.OpenKey(reg, subkey, 0, winreg.KEY_READ) as sub_reg:
                            for value in ["Debugger", "UseFilter", "GlobalFlag", "MitigationOptions"]:
                                try:
                                    winreg.QueryValueEx(sub_reg, value)
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
        try:
            wallpaper = os.path.join(self.path_system, "web", "wallpaper", "Windows", "img0.jpg")
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", 0, winreg.KEY_READ) as reg:
                val, _ = winreg.QueryValueEx(reg, "Wallpaper")
                if val != wallpaper:
                    return True
        except Exception:
            pass
        return False

    def execute_system_repair(self, items):
        try:
            if "mbr" in items:
                self.repair_system_mbr()
            if "restrict" in items:
                self.repair_system_restrict()
            if "file_type" in items:
                self.repair_system_file_type()
            if "file_icon" in items:
                self.repair_system_file_icon()
            if "image" in items:
                self.repair_system_image()
            if "wallpaper" in items:
                self.repair_system_wallpaper()

            self.write_log("INFO", "System Repair", detail=f"Repaired {len(items)} items", operate=True)
            return True
        except Exception as e:
            self.write_log("WARN", "execute_system_repair", detail=str(e), operate=True, success=False)
            return False

####################################################################################################

    def reset_config(self):
        with self.lock_config:
            self.pyas_config = self.pyas_default.copy()
            self.write_log("INFO", "Config Update", detail="Reset to default")
            self.save_config()
        return True

    def open_website(self):
        try:
            webbrowser.open("https://pyas-security.com/antivirus")
            return True
        except Exception:
            return False

    def open_url(self, url):
        try:
            webbrowser.open(url)
            return True
        except Exception:
            return False

    def check_update(self):
        try:
            current = self.pyas_config.get("version", "0.0.0")
            j = requests.get("https://api.github.com/repos/87owo/PYAS/releases/latest", headers={"Accept": "application/vnd.github+json", "User-Agent": "PYAS"}, timeout=10).json()
            latest = str(j.get("tag_name") or j.get("name") or "").strip()
            page = j.get("html_url") or "https://github.com/87owo/PYAS/releases"
            
            if latest:
                rl = re.sub(r"^[vV]\s*", "", latest)
                cl = re.sub(r"^[vV]\s*", "", current)
                tr = tuple(int(x) for x in re.findall(r"\d+", rl))
                tl = tuple(int(x) for x in re.findall(r"\d+", cl))
                if tr > tl:
                    return {"has_update": True, "latest": latest, "current": current, "url": page}
                return {"has_update": False, "latest": latest, "current": current, "url": page}

        except Exception:
            pass
        return {"error": True}

####################################################################################################

    def list_process(self):
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        snapshot = self.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        result = []
        
        if snapshot in (-1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            return result
            
        success = self.kernel32.Process32FirstW(snapshot, ctypes.byref(pe))
        while success:
            pid = pe.th32ProcessID
            name, file_path = None, None
            if pid > 4:
                name, file_path = self.get_exe_info(pid)
            if not name:
                try:
                    name = pe.szExeFile
                except Exception:
                    name = "Unknown"
            result.append({"pid": pid, "name": name, "path": file_path or "None"})
            success = self.kernel32.Process32NextW(snapshot, ctypes.byref(pe))
            
        self.kernel32.CloseHandle(snapshot)
        return result

    def kill_process(self, pid):
        try:
            h = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if h:
                try:
                    file_path = self.norm_path(self.get_process_file(h))
                    if self.path_equal(file_path, self.file_pyas):
                        return False
                    else:
                        self.kernel32.TerminateProcess(h, 0)
                        return True
                finally:
                    self.kernel32.CloseHandle(h)

        except Exception as e:
            self.write_log("WARN", "kill_process", pid=pid, detail=str(e), operate=True, success=False)
        return False

####################################################################################################

    def get_process_file(self, h_process):
        buf = ctypes.create_unicode_buffer(1024)
        if self.psapi.GetProcessImageFileNameW(h_process, buf, 1024):
            return self.norm_path(self.device_path_to_drive(buf.value))
        return ""

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
                else:
                    if self.psapi.GetProcessImageFileNameW(h, buf, 1024):
                        path = self.norm_path(self.device_path_to_drive(buf.value))
                        if path:
                            file_path = path
                            name = os.path.basename(path)
            finally:
                self.kernel32.CloseHandle(h)
        return name, file_path

    def device_path_to_drive(self, path):
        if not path:
            return ""

        for d in range(65, 91):
            drive = f"{chr(d)}:"
            buf = ctypes.create_unicode_buffer(1024)
            if self.kernel32.QueryDosDeviceW(drive, buf, 1024):
                dev = buf.value
                if path.startswith(dev):
                    return path.replace(dev, drive, 1)
        return path

####################################################################################################

    def lock_file(self, file, lock):
        with self.lock_file_ops:
            try:
                if lock:
                    if file not in self.virus_lock:
                        fd = os.open(file, os.O_RDWR | os.O_BINARY)
                        try:
                            try:
                                size = os.path.getsize(file)
                            except Exception:
                                size = 1

                            lock_size = size if size > 0 else 1
                            msvcrt.locking(fd, msvcrt.LK_NBRLCK, lock_size)
                            self.virus_lock[file] = (fd, lock_size)

                        except Exception:
                            os.close(fd)
                            raise
                else:
                    if file in self.virus_lock:
                        fd, lock_size = self.virus_lock[file]
                        try:
                            msvcrt.locking(fd, msvcrt.LK_UNLCK, lock_size)
                        finally:
                            os.close(fd)
                            del self.virus_lock[file]

            except Exception as e:
                self.write_log("WARN", "lock_file", source=file, detail=str(e), success=False)

    def relock_file(self):
        with self.lock_config:
            quarantine_list = self.pyas_config.get("quarantine", [])

        for item in quarantine_list:
            file = item["file"]
            if os.path.exists(file):
                self.lock_file(file, True)

####################################################################################################

    def calc_file_hash(self, file_path, block_size=65536):
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(block_size), b""):
                    h.update(chunk)

            return h.hexdigest()
        except Exception:
            return None

    def manage_named_list(self, list_key, files, action="add", lock_func=None):
        if list_key == "quarantine" and lock_func is None:
            lock_func = self.lock_file

        norm_paths = self.norm_path(files or [], must_exist=True)
        if isinstance(norm_paths, str):
            norm_paths = [norm_paths] if norm_paths else []

        acted_items = []
        with self.lock_config:
            target_list = self.pyas_config.setdefault(list_key, [])
            
            if action == "add":
                for path in norm_paths:
                    exists = any(self.norm_path(item.get("file", "")) == path for item in target_list if isinstance(item, dict))
                    if not exists:
                        if lock_func:
                            lock_func(path, True)
                        target_list.append({"file": path})
                        acted_items.append(path)
                        if list_key == "white_list":
                            self.sync_driver_whitelist(path, True)
            elif action == "remove":
                for item in list(target_list):
                    file_path = self.norm_path(item.get("file", ""))
                    if isinstance(item, dict) and file_path in norm_paths:
                        if lock_func:
                            lock_func(file_path, False)
                        target_list.remove(item)
                        acted_items.append(file_path)
                        if list_key == "white_list":
                            self.sync_driver_whitelist(file_path, False)

            if acted_items:
                self.write_log("INFO", "Config Update", detail=f"List [{list_key}] {action}: {acted_items}")
                self.save_config()
        return len(acted_items)

    def is_in_whitelist(self, file_path):
        p = self.norm_path(file_path)
        if not p:
            return False

        with self.lock_config:
            whitelist = self.pyas_config.get("white_list", [])
            
        p_norm = os.path.normcase(p)
        return any(os.path.normcase(item.get("file", "")) == p_norm for item in whitelist if isinstance(item, dict))

    def init_whitelist(self):
        self.manage_named_list("white_list", [self.file_pyas], action="add")

####################################################################################################

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
                    self.thread_pool.submit(self.handle_new_process, pid)

            except Exception as e:
                self.write_log("WARN", "protect_proc_thread", detail=str(e), success=False)

    def get_process_list(self):
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        snapshot = self.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        result = []
        
        if snapshot in (-1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            return result
            
        try:
            success = self.kernel32.Process32FirstW(snapshot, ctypes.byref(pe))
            while success:
                pid = pe.th32ProcessID
                name, file_path = None, None
                if pid > 4:
                    name, file_path = self.get_exe_info(pid)

                if not name:
                    try:
                        name = pe.szExeFile
                    except Exception:
                        name = "Unknown"

                result.append({"pid": pid, "name": name, "path": file_path or "None"})
                success = self.kernel32.Process32NextW(snapshot, ctypes.byref(pe))
        finally:
            self.kernel32.CloseHandle(snapshot)
            
        return result

    def get_process_list_pids(self):
        exist_process = set()
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        hSnapshot = self.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        
        if hSnapshot in (-1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            return exist_process
            
        try:
            if self.kernel32.Process32FirstW(hSnapshot, ctypes.byref(pe)):
                while True:
                    exist_process.add(pe.th32ProcessID)
                    if not self.kernel32.Process32NextW(hSnapshot, ctypes.byref(pe)):
                        break
        finally:
            self.kernel32.CloseHandle(hSnapshot)
            
        return exist_process

####################################################################################################

    def handle_new_process(self, pid):
        h = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
        if not h:
            return

        self.ntdll.NtSuspendProcess(h)
        try:
            cmdline = self.get_process_cmdline(h)
            
            if "-scan" in cmdline and self.path_equal(self.get_process_file(h), self.file_pyas):
                return
                
            paths = self.extract_paths_from_cmdline(cmdline)
            with self.lock_config:
                suffix = self.pyas_config.get("suffix", [])
                
            for p in paths:
                file_path = self.norm_path(self.device_path_to_drive(p))
                if not file_path or not os.path.isfile(file_path):
                    continue

                ext = os.path.splitext(file_path)[-1].lower()
                if ext not in suffix:
                    continue
                if self.is_in_whitelist(file_path):
                    continue
                
                self.cloud_check(file_path)
                if self.scan_engine(file_path):
                    self.kernel32.TerminateProcess(h, 0)
                    self.write_log("BLOCK", "Process Block", pid=pid, source=file_path, file_hash=self.calc_file_hash(file_path))
                    break
        finally:
            self.ntdll.NtResumeProcess(h)
            self.kernel32.CloseHandle(h)

####################################################################################################

    def get_process_cmdline(self, h):
        pbi = PROCESS_BASIC_INFORMATION()
        retlen = ctypes.wintypes.ULONG(0)
        status = self.ntdll.NtQueryInformationProcess(h, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(retlen))
        if status != 0:
            return ""

        pointer_size = ctypes.sizeof(ctypes.c_void_p)
        peb_address = int(pbi.PebBaseAddress) if pbi.PebBaseAddress else 0
        read_buf = (ctypes.c_ubyte * pointer_size)()
        lpNumberOfBytesRead = ctypes.c_size_t(0)
        offset_process_parameters = 0x20 if pointer_size == 8 else 0x10

        addr_pp = peb_address + offset_process_parameters
        if not addr_pp:
            return ""
        if not self.kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr_pp), read_buf, pointer_size, ctypes.byref(lpNumberOfBytesRead)):
            return ""

        proc_params_address = ctypes.c_void_p.from_buffer_copy(read_buf).value
        if not proc_params_address:
            return ""

        offset_command_line = 0x70 if pointer_size == 8 else 0x40
        us = UNICODE_STRING()
        addr_cmd = int(proc_params_address) + offset_command_line
        if not self.kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr_cmd), ctypes.byref(us), ctypes.sizeof(us), ctypes.byref(lpNumberOfBytesRead)):
            return ""
        if not us.Buffer or us.Length == 0:
            return ""

        buf_len = int(us.Length // 2)
        buf = (ctypes.c_wchar * buf_len)()
        if not self.kernel32.ReadProcessMemory(h, ctypes.c_void_p(int(us.Buffer)), buf, us.Length, ctypes.byref(lpNumberOfBytesRead)):
            return ""
        return "".join(buf)

    def extract_paths_from_cmdline(self, cmdline):
        if not cmdline:
            return []

        argc = ctypes.c_int(0)
        argv = self.shell32.CommandLineToArgvW(cmdline, ctypes.byref(argc))
        if not argv:
            return []

        args = [argv[i] for i in range(argc.value)]
        self.kernel32.LocalFree(ctypes.cast(argv, ctypes.c_void_p))

        patterns = [r'([A-Za-z]:\\[^"\']+)', r'(\\\\[^"\']+)', r'(\.\\[^"\']+)', r'(\./[^"\']+)', r'([A-Za-z]:/[^"\']+)', r'([^\s]*\\[^\s]+)']
        found = []
        for arg in args:
            for p in patterns:
                for m in re.finditer(p, arg):
                    found.append(m.group(1).strip('"').strip("'"))

        return list(dict.fromkeys(found))

####################################################################################################

    def protect_file_thread(self):
        hDir = self.kernel32.CreateFileW(self.path_user, 0x0001, 0x00000007, None, 3, 0x02000000, None)
        if not hDir or hDir == -1:
            return

        try:
            buffer = ctypes.create_string_buffer(65536)
            temp_prefix = os.path.normcase(self.path_temp)
            if not temp_prefix.endswith(os.sep):
                temp_prefix += os.sep

            while True:
                with self.lock_config:
                    if not self.pyas_config.get("document_switch", False):
                        break
                try:
                    bytes_returned = ctypes.wintypes.DWORD()
                    res = self.kernel32.ReadDirectoryChangesW(hDir, buffer, ctypes.sizeof(buffer), True, 0x0000001F, ctypes.byref(bytes_returned), None, None)
                    if not res or bytes_returned.value == 0:
                        continue

                    offset = 0
                    while True:
                        notify = FILE_NOTIFY_INFORMATION.from_buffer(buffer, offset)
                        raw_filename = notify.FileName[:notify.FileNameLength // 2]
                        
                        if raw_filename and notify.Action in [2, 3, 4]:
                            file_path = self.norm_path(os.path.join(self.path_user, raw_filename), must_exist=True)
                            if file_path and not self.is_in_whitelist(file_path):
                                norm_path = os.path.normcase(file_path)
                                
                                is_temp_mei = False
                                if norm_path.startswith(temp_prefix):
                                    sub_path = norm_path[len(temp_prefix):]
                                    if sub_path.startswith("_mei"):
                                        is_temp_mei = True
                                        
                                if not is_temp_mei:
                                    with self.lock_config:
                                        suffix = self.pyas_config.get("suffix", [])
                                        
                                    ext = os.path.splitext(file_path)[-1].lower()
                                    if ext in suffix:
                                        self.thread_pool.submit(self.handle_new_file, file_path)

                        if notify.NextEntryOffset == 0:
                            break
                        offset += notify.NextEntryOffset

                except Exception as e:
                    self.write_log("WARN", "protect_file_thread", detail=str(e), success=False)
        finally:
            self.kernel32.CloseHandle(hDir)

    def handle_new_file(self, file_path):
        try:
            for _ in range(3):
                size1 = os.path.getsize(file_path)
                time.sleep(0.5)
                size2 = os.path.getsize(file_path)
                if size1 == size2 and size1 > 0:
                    break
            else:
                return

            with self.lock_file_ops:
                if file_path in self.virus_lock:
                    return

            if self.scan_engine(file_path):
                if self.manage_named_list("quarantine", [file_path], action="add", lock_func=self.lock_file) > 0:
                    self.write_log("BLOCK", "File Block", source=file_path, file_hash=self.calc_file_hash(file_path))
                    self.cloud_check(file_path)
        except Exception:
            pass

####################################################################################################

    def protect_net_thread(self):
        with self.lock_net:
            self.exist_connections = set()
            
        while True:
            with self.lock_config:
                if not self.pyas_config.get("network_switch", False):
                    break
            try:
                time.sleep(0.5)
                conns = self.get_connections_list()

                with self.lock_net:
                    new_conns = conns - self.exist_connections
                    self.exist_connections = conns

                for key in new_conns:
                    self.thread_pool.submit(self.handle_new_connection, key)

            except Exception as e:
                self.write_log("WARN", "protect_net_thread", detail=str(e), success=False)

        with self.lock_net:
            self.exist_connections = set()

    def get_connections_list(self):
        connections = set()
        try:
            size = ctypes.wintypes.DWORD()
            ret = self.iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), True, 2, 5, 0)
            if ret != 122:
                return connections

            buf = ctypes.create_string_buffer(size.value)
            ret = self.iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), True, 2, 5, 0)
            if ret != 0:
                return connections

            num_entries = ctypes.cast(buf, ctypes.POINTER(ctypes.wintypes.DWORD)).contents.value
            row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
            offset = ctypes.sizeof(ctypes.wintypes.DWORD)

            for i in range(num_entries):
                entry_addr = ctypes.addressof(buf) + offset + i * row_size
                row = MIB_TCPROW_OWNER_PID.from_address(entry_addr)
                connections.add((row.dwOwningPid, row.dwRemoteAddr, row.dwRemotePort))

        except Exception:
            pass
        return connections

    def handle_new_connection(self, key):
        pid, remote_addr, remote_port = key
        try:
            h = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if not h:
                return
            
            try:
                remote_ip = f"{remote_addr & 0xFF}.{(remote_addr >> 8) & 0xFF}.{(remote_addr >> 16) & 0xFF}.{(remote_addr >> 24) & 0xFF}"
                file_path = self.norm_path(self.get_process_file(h))
                
                if file_path and not self.is_in_whitelist(file_path):
                    if hasattr(self.heuristic, "network") and remote_ip in self.heuristic.network:
                        self.kernel32.TerminateProcess(h, 0)
                        self.write_log("BLOCK", "Network Block", pid=pid, source=file_path, target=remote_ip, file_hash=self.calc_file_hash(file_path))
            finally:
                self.kernel32.CloseHandle(h)

        except Exception as e:
            self.write_log("WARN", "handle_new_connection", pid=key[0], detail=str(e), success=False)

####################################################################################################

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

####################################################################################################

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
                    title = ctypes.create_unicode_buffer(length + 1)
                    self.user32.GetWindowTextW(hwnd, title, length + 1)
                    class_name = ctypes.create_unicode_buffer(256)
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
            for item in target_list:
                if item.get("exe") == rule.get("exe") and item.get("class") == rule.get("class") and item.get("title") == rule.get("title"):
                    return False

            target_list.append(rule)
            self.write_log("INFO", "Config Update", detail=f"List [block_list] add: {rule}")
            self.save_config()
            return True

####################################################################################################

    def repair_system_restrict(self):
        try:
            permissions, restrict_paths = self._get_restrict_lists()
            for hkey, path in restrict_paths:
                try:
                    with winreg.OpenKey(hkey, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WRITE) as reg:
                        for val in permissions:
                            try:
                                winreg.DeleteValue(reg, val)
                            except FileNotFoundError:
                                pass
                except Exception:
                    pass
        except Exception as e:
            self.write_log("WARN", "repair_system_restrict", detail=str(e), success=False)

    def repair_system_file_type(self):
        try:
            for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                for ext in [".exe", ".bat", ".cmd", ".com"]:
                    try:
                        with winreg.CreateKey(root, rf"SOFTWARE\Classes\{ext}") as reg:
                            winreg.SetValue(reg, "", winreg.REG_SZ, "exefile" if ext == ".exe" else ext[1:]+"file")
                    except Exception:
                        pass
                for shell_cmd in ["open", "runas"]:
                    try:
                        with winreg.CreateKey(root, rf"SOFTWARE\Classes\exefile\shell\{shell_cmd}\command") as reg:
                            winreg.SetValue(reg, "", winreg.REG_SZ, '"%1" %*')
                    except Exception:
                        pass
        except Exception as e:
            self.write_log("WARN", "repair_system_file_type", detail=str(e), success=False)

    def repair_system_file_icon(self):
        try:
            for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                try:
                    with winreg.CreateKey(root, r"SOFTWARE\Classes\exefile\DefaultIcon") as reg:
                        winreg.SetValue(reg, "", winreg.REG_SZ, "%1")
                except Exception:
                    pass
        except Exception as e:
            self.write_log("WARN", "repair_system_file_icon", detail=str(e), success=False)

    def repair_system_image(self):
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS) as reg:
                i = 0
                while True:
                    try:
                        subkey = winreg.EnumKey(reg, i)
                        with winreg.OpenKey(reg, subkey, 0, winreg.KEY_ALL_ACCESS) as sub_reg:
                            for value in ["Debugger", "UseFilter", "GlobalFlag", "MitigationOptions"]:
                                try:
                                    winreg.DeleteValue(sub_reg, value)
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

            key = r"Control Panel\Desktop"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as reg:
                winreg.SetValueEx(reg, "Wallpaper", 0, winreg.REG_SZ, wallpaper)

            theme_dir = os.path.join(self.path_appdata, "Microsoft", "Windows", "Themes")
            for fname in ["TranscodedWallpaper", "TranscodedWallpaper.tmp"]:
                fpath = os.path.join(theme_dir, fname)
                if os.path.exists(fpath):
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass

            cache_dir = os.path.join(theme_dir, "CachedFiles")
            if os.path.exists(cache_dir):
                try:
                    shutil.rmtree(cache_dir, ignore_errors=True)
                except Exception:
                    pass

            self.user32.SystemParametersInfoW(20, 0, wallpaper, 3)
        except Exception as e:
            self.write_log("WARN", "repair_system_wallpaper", detail=str(e), success=False)

    def repair_system_mbr(self):
        if not self.mbr_backup:
            return

        for drive, mbr_value in self.mbr_backup.items():
            drive_path = rf"\\.\PhysicalDrive{drive}"
            try:
                with open(drive_path, "rb+") as f:
                    current = f.read(512)
                    if current != mbr_value:
                        f.seek(0)
                        f.write(mbr_value)
                        self.write_log("INFO", "MBR Repaired", source=drive_path, operate=True)

            except Exception:
                pass

####################################################################################################

    def check_process_survival(self):
        target_map = {"explorer.exe": "explorer.exe"}
        try:
            running = set()
            pe = PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            snapshot = self.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)

            if snapshot not in (-1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
                try:
                    if self.kernel32.Process32FirstW(snapshot, ctypes.byref(pe)):
                        while True:
                            try:
                                running.add(pe.szExeFile.lower())
                            except Exception:
                                pass

                            if not self.kernel32.Process32NextW(snapshot, ctypes.byref(pe)):
                                break
                finally:
                    self.kernel32.CloseHandle(snapshot)

            for name, cmd in target_map.items():
                if name.lower() not in running:
                    subprocess.Popen(cmd, shell=True)
                    self.write_log("INFO", "System Restart", source=name)

        except Exception:
            pass

####################################################################################################

    def install_system_driver(self):
        try:
            service_name = "PYAS_Driver"
            cmd = f'sc create {service_name} binPath="{self.path_drivers}" type=kernel start=demand error=normal depend=FltMgr group="FSFilter Activity Monitor"'
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
            
            key_path = r"SYSTEM\CurrentControlSet\Services\PYAS_Driver\Instances"
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                winreg.SetValueEx(key, "DefaultInstance", 0, winreg.REG_SZ, "PYAS Instance")

            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, rf"{key_path}\PYAS Instance") as key:
                winreg.SetValueEx(key, "Altitude", 0, winreg.REG_SZ, "320000")
                winreg.SetValueEx(key, "Flags", 0, winreg.REG_DWORD, 0)
                
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

            time.sleep(0.5)
            subprocess.run(["sc", "stop", "PYAS_Driver"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
            subprocess.run(["sc", "delete", "PYAS_Driver"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
            return True

        except Exception:
            return False

    def check_system_driver(self):
        try:
            result = subprocess.run(["sc", "query", "PYAS_Driver"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
            return "RUNNING" in result.stdout

        except Exception:
            return False

####################################################################################################

    def pipe_server_thread(self):
        try:
            port_name = "\\PYAS_Output_Pipe"

            while True:
                with self.lock_config:
                    if not self.pyas_config.get("driver_switch", False): break

                temp_port = ctypes.wintypes.HANDLE()

                hr = self.fltlib.FilterConnectCommunicationPort(port_name, 0, None, 0, None, ctypes.byref(temp_port))
                if hr == 0:
                    with self.lock_driver:
                        self.driver_port = temp_port

                    with self.lock_config:
                        whitelist = self.pyas_config.get("white_list", [])
                    for item in whitelist:
                        if isinstance(item, dict) and item.get("file"):
                            self.sync_driver_whitelist(item["file"], True)

                    message = PYAS_FULL_MESSAGE()
                    while True:
                        with self.lock_config:
                            if not self.pyas_config.get("driver_switch", False): break
                        
                        with self.lock_driver:
                            current_port = self.driver_port
                        
                        if not current_port:
                            break

                        try:
                            hr_get = self.fltlib.FilterGetMessage(current_port, ctypes.byref(message), ctypes.sizeof(PYAS_FULL_MESSAGE), None)
                        except OSError:
                            break

                        if hr_get == 0:
                            code = message.Data.MessageCode
                            pid = message.Data.ProcessId
                            raw_path = self.get_exe_info(pid)[1]
                            target = message.Data.Path

                            with self.lock_config:
                                block_codes = self.pyas_config.get("block", [])

                            if code in block_codes and not self.is_in_whitelist(raw_path):
                                self.kill_process(pid)
                                self.write_log("BLOCK", "Driver Block", pid=pid, source=raw_path, target=target, code=code, file_hash=self.calc_file_hash(raw_path))
                        else:
                            break

                    with self.lock_driver:
                        if self.driver_port:
                            self.kernel32.CloseHandle(self.driver_port)
                            self.driver_port = None

                time.sleep(0.2)
        except Exception as e:
            self.write_log("WARN", "pipe_server_thread", detail=str(e), success=False)

####################################################################################################

    def popup_intercept_thread(self):
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
        hwnd_list = []
        
        def enum_windows_callback(hWnd, lParam):
            if self.user32.IsWindowVisible(hWnd):
                hwnd_list.append(hWnd)
            return True
            
        enum_cb = WNDENUMPROC(enum_windows_callback)

        while True:
            try:
                time.sleep(0.5)
                with self.lock_config:
                    rules = self.pyas_config.get("block_list", [])
                    cur_ver = self.pyas_config.get("version", "0.0.0")

                hwnd_list.clear()
                self.user32.EnumWindows(enum_cb, 0)
                
                for hWnd in list(hwnd_list):
                    pid = ctypes.c_ulong(0)
                    self.user32.GetWindowThreadProcessId(hWnd, ctypes.byref(pid))
                    
                    if pid.value <= 4:
                        continue
                        
                    proc_name, file_path = self.get_exe_info(pid.value)

                    if proc_name != "PYAS_Setup.exe" and not rules:
                        continue
                    
                    length = self.user32.GetWindowTextLengthW(hWnd)
                    title = ctypes.create_unicode_buffer(length + 1)
                    self.user32.GetWindowTextW(hWnd, title, length + 1)
                    class_name = ctypes.create_unicode_buffer(256)
                    self.user32.GetClassNameW(hWnd, class_name, 256)
                    
                    t_str = str(title.value)
                    c_str = str(class_name.value)

                    if proc_name == "PYAS_Setup.exe" and c_str == "WindowClass_0" and t_str == "PYAS Setup":
                        if file_path:
                            setup_ver = self.get_file_version(file_path)
                            if self.compare_versions(setup_ver, cur_ver):
                                self.close()

                    if not rules:
                        continue

                    is_pass = any(item.get("exe") == proc_name or item.get("class") == c_str for item in self.pass_windows)
                    if is_pass:
                        continue
                    
                    is_block = any(item.get("exe") == proc_name or item.get("class") == c_str or item.get("title") == t_str for item in rules)
                    if is_block:
                        for msg in [0x0010, 0x0002, 0x0012, 0x0112]:
                            self.user32.SendMessageW(hWnd, msg, 0xF060, 0)
                        if proc_name:
                            self.kill_process(pid.value)

            except Exception:
                pass

####################################################################################################

    def select_files(self):
        if self._window:
            result = self._window.create_file_dialog(webview.FileDialog.OPEN, allow_multiple=True)
            return result or []
        return []

    def select_folder(self):
        if self._window:
            result = self._window.create_file_dialog(webview.FileDialog.FOLDER)
            return result or []
        return []

####################################################################################################

def get_base_path():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

####################################################################################################

class NoCacheRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        web_dir = os.path.join(get_base_path(), "Interface")
        super().__init__(*args, directory=web_dir, **kwargs)

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
        self.title = title
        self.api_ref = api_ref
        self.old_wndproc = None
        self.WM_DPICHANGED = 0x02E0
        self.WM_NCHITTEST = 0x0084
        self.WM_COPYDATA = 0x004A
        self.HTCAPTION = 2
        self.GWLP_WNDPROC = -4

        class RECT(ctypes.Structure):
            _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long), 
                        ("right", ctypes.c_long), ("bottom", ctypes.c_long)]
        self.RECT = RECT
        
        self.WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p)
        self.new_wndproc_cb = self.WNDPROC(self.wndproc)
        self.user32 = ctypes.windll.user32

        self.user32.CallWindowProcW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
        self.user32.CallWindowProcW.restype = ctypes.c_void_p

        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.SetWindowLong = self.user32.SetWindowLongPtrW
            self.GetWindowLong = self.user32.GetWindowLongPtrW
        else:
            self.SetWindowLong = self.user32.SetWindowLongW
            self.GetWindowLong = self.user32.GetWindowLongW

        self.SetWindowLong.argtypes = [ctypes.c_void_p, ctypes.c_int, self.WNDPROC]
        self.SetWindowLong.restype = ctypes.c_void_p
        self.GetWindowLong.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.GetWindowLong.restype = ctypes.c_void_p

    def hook(self):
        hwnd = self.user32.FindWindowW(None, self.title)
        if hwnd:
            self.old_wndproc = self.GetWindowLong(hwnd, self.GWLP_WNDPROC)
            self.SetWindowLong(hwnd, self.GWLP_WNDPROC, self.new_wndproc_cb)

    def wndproc(self, hwnd, msg, wparam, lparam):
        if msg in [0x0010, 0x0002, 0x0012, 0x0212]:
            return 0
        
        if msg == 0x0112 and (wparam & 0xFFF0) == 0xF060:
            return 0
            
        if msg == self.WM_COPYDATA:
            try:
                cds = ctypes.cast(lparam, ctypes.POINTER(COPYDATASTRUCT)).contents
                if cds.dwData == 1:
                    buffer = ctypes.string_at(cds.lpData, cds.cbData)
                    path = buffer.decode('utf-8').strip('\x00')
                    if self.api_ref:
                        if self.api_ref._window:
                            self.api_ref._window.restore()
                            self.api_ref._window.show()
                        threading.Thread(target=self.api_ref.trigger_context_scan, args=(path,), daemon=True).start()
                elif cds.dwData == 2:
                    if self.api_ref and self.api_ref._window:
                        self.api_ref._window.restore()
                        self.api_ref._window.show()
            except Exception:
                pass
            return 1

        if msg == self.WM_NCHITTEST:
            x = lparam & 0xFFFF
            if x >= 32768: x -= 65536
            y = (lparam >> 16) & 0xFFFF
            if y >= 32768: y -= 65536
            
            rect = self.RECT()
            self.user32.GetWindowRect(hwnd, ctypes.byref(rect))
            
            if rect.top <= y <= rect.top + 44 and rect.left <= x <= rect.right - 150:
                return self.HTCAPTION

        if msg == self.WM_DPICHANGED:
            rect = ctypes.cast(lparam, ctypes.POINTER(self.RECT)).contents
            self.user32.SetWindowPos(hwnd, None, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, 0x0004 | 0x0010 | 0x0020)

        if self.old_wndproc:
            return self.user32.CallWindowProcW(self.old_wndproc, hwnd, msg, wparam, lparam)

        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

####################################################################################################

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def start_api(port):
    TCPServer.allow_reuse_address = True
    with TCPServer(("127.0.0.1", port), NoCacheRequestHandler) as httpd:
        httpd.serve_forever()

####################################################################################################

if __name__ == "__main__":
    hide_on_start = "-h" in sys.argv or "-hide" in sys.argv
    init_width, init_height = 980, 670

    port = get_free_port()

    api_thread = threading.Thread(target=start_api, args=(port,), daemon=True)
    api_thread.start()

    js_api = WindowAPI()

    user32 = ctypes.windll.user32
    screen_width = user32.GetSystemMetrics(0)
    screen_height = user32.GetSystemMetrics(1)
    pos_x = (screen_width - init_width) // 2
    pos_y = (screen_height - init_height) // 2

    window = webview.create_window(
        title="PYAS Security", url=f"http://127.0.0.1:{port}/",
        width=init_width, height=init_height, x=pos_x, y=pos_y,
        frameless=True, easy_drag=False, js_api=js_api,
        background_color='#e0e0e0', hidden=hide_on_start)

    if platform.system() == "Windows":
        window_hook = WindowHook("PYAS Security", js_api)
        window.events.shown += window_hook.hook

    js_api.set_window(window)
    js_api.show_tray()

    webview.start()
