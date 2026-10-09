from PYAS_Diagnostics import log_exception, report_log_path
import os
import sys
import time
import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from PYAS_Engine import rule_scanner, pe_scanner, cloud_scanner
from PYAS_Version import VERSION


class RuntimeMixin:
    def init_environ(self):
        self.python = sys.executable

        if getattr(sys, "frozen", False):
            self.file_pyas = self.norm_path(sys.executable)
        else:
            self.file_pyas = self.norm_path(os.path.abspath(sys.argv[0]))

        self.args_pyas = sys.argv[1:]
        self.path_pyas = os.path.dirname(self.file_pyas)
        self.pid_pyas = int(os.getpid())

        self.path_appdata = os.environ.get("APPDATA")
        self.path_localappdata = os.environ.get("LOCALAPPDATA") or self.path_appdata
        self.path_name = os.environ.get("USERNAME")
        self.path_temp = os.environ.get(
            "TEMP", f"C:\\Users\\{self.path_name}\\AppData\\Local\\Temp"
        )
        self.path_config = os.environ.get("ALLUSERSPROFILE", "C:\\ProgramData")
        self.path_system = os.environ.get("SYSTEMROOT", "C:\\Windows")
        self.path_user = os.environ.get("USERPROFILE", f"C:\\Users\\{self.path_name}")

        self.path_systemp = os.path.join(self.path_system, "Temp")
        self.file_config = os.path.join(self.path_config, "PYAS", "Config.json")
        self.file_log = report_log_path()
        self.path_webview = os.path.join(
            self.path_localappdata or self.path_temp, "PYAS", "WebView2"
        )
        self.file_webview_log = self.file_log
        self.path_properties = os.path.join(self.path_pyas, "Engine", "Properties")
        self.path_heuristic = os.path.join(self.path_pyas, "Engine", "Heuristic")
        self.path_protect = os.path.join(self.path_pyas, "Plugins", "Filter")
        self.path_rules = os.path.join(self.path_pyas, "Plugins", "Rules")
        self.path_drivers = os.path.join(self.path_protect, "PYAS_Driver.sys")

    def init_variables(self):
        self.lock_workers = threading.RLock()
        self.feature_workers = {}
        self.feature_restarts = set()

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

        self.ui_ready_event = threading.Event()
        self.engine_initialized = False

        self.scan_running = False
        self.scan_preparing = False
        self.scan_stop_requested = False
        self.scan_finished = False

        self.virus_lock = {}
        self.virus_results = []

        self.scan_count = 0
        self.scan_events = {}
        self.hash_cache = {}
        self.file_scheduler = None

        self.mbr_backup = {}

        self.cloud_pending = set()
        self.cloud_cancel_event = threading.Event()

        self.autostart_mode = "unknown"

        self.last_io_counters = {}
        self.last_io_time = time.time()
        self.suspended_procs = set()

        self.lock_driver = threading.RLock()
        self.lock_driver_unload = threading.Lock()
        self.driver_unload_worker = None
        self.driver_unload_result = None
        self.closing = False

        self.lock_update = threading.RLock()
        self.lock_proc = threading.RLock()
        self.lock_net = threading.RLock()
        self.lock_io = threading.RLock()

        self.pyas_default = {
            "version": VERSION,
            "api_host": "https://pyas-security.com/",
            "api_key": "fBRZxYS1UxykM-qzNOlKOEl63WILzlvgNMn6QfsG6FXCAAIktCrOPTAfY5_hEyuZ",
            "suffix": [
                ".exe",
                ".dll",
                ".sys",
                ".ocx",
                ".scr",
                ".efi",
                ".acm",
                ".ax",
                ".cpl",
                ".drv",
                ".com",
                ".mui",
                ".pyd",
                ".wfx",
                ".api",
                ".awx",
                ".rll",
                ".winmd",
                ".bat",
                ".cmd",
                ".ps1",
                ".vbs",
                ".vbe",
                ".wsf",
                ".reg",
                ".html",
                ".js",
                ".jse",
                ".jsp",
                ".php",
                ".hta",
                ".lnk",
                ".py",
                ".sh",
                ".url",
                ".rtf",
                ".ini",
            ],
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
            "block_list": [],
        }

        self.pass_windows = [
            {"exe": "System Idle Process", "class": "", "title": ""},
            {"exe": "", "class": "Windows.UI.Core.CoreWindow", "title": ""},
            {"exe": "explorer.exe", "class": "", "title": ""},
        ]

        self.scan_pool = ThreadPoolExecutor(max_workers=2)
        self.protect_pool = ThreadPoolExecutor(max_workers=8)
        self.proc_pool = ThreadPoolExecutor(max_workers=16)
        self.start_daemon_thread(self.log_flush_thread)

        for _ in range(2):
            self.start_daemon_thread(self.cloud_worker)

    def ui_dispatcher_thread(self):
        while not getattr(self, "closing", False):
            batch = []

            try:
                batch.append(self.ui_queue.get(timeout=0.1))

                while len(batch) < 50:
                    try:
                        batch.append(self.ui_queue.get_nowait())
                    except queue.Empty:
                        break

                if self._window:
                    self._window.evaluate_js("".join(batch))
            except queue.Empty:
                continue
            except Exception:
                log_exception("PYAS_Runtime.RuntimeMixin.ui_dispatcher_thread:146")
                pass
            finally:
                for _ in batch:
                    self.ui_queue.task_done()

    def start_feature_thread(self, target, switch):
        with self.lock_workers:
            existing = self.feature_workers.get(switch)

            if existing and existing.is_alive():
                self.feature_restarts.add(switch)
                return existing

            def worker():
                try:
                    while True:
                        try:
                            target()
                        except Exception:
                            log_exception(f"RuntimeMixin.{target.__name__}")

                        with self.lock_config:
                            enabled = self.pyas_config.get(switch, False)

                        if not enabled or self.closing:
                            break

                        self.write_log(
                            "WARN",
                            "Protection Recovery",
                            detail=f"Restarting {switch}",
                            success=False,
                        )
                        time.sleep(0.5)
                finally:
                    with self.lock_workers:
                        if self.feature_workers.get(switch) is threading.current_thread():
                            self.feature_workers.pop(switch, None)

                        restart = switch in self.feature_restarts
                        self.feature_restarts.discard(switch)

                    with self.lock_config:
                        enabled = self.pyas_config.get(switch, False)

                    if restart and enabled and not self.closing:
                        self.start_feature_thread(target, switch)

            thread = threading.Thread(target=worker, daemon=True, name=f"PYAS.{target.__name__}")
            self.feature_workers[switch] = thread
            thread.start()
            return thread
