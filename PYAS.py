import os, gc, re, sys, time, json, base64
import ctypes, ctypes.wintypes, threading
import requests, webbrowser, winreg, shutil
import traceback, hashlib, msvcrt, pyperclip

from PYAS_Config import *
from PYAS_Engine import *
from PYAS_Interface import *

from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtGui import *

####################################################################################################

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.wintypes.DWORD),
        ("cntUsage", ctypes.wintypes.DWORD),
        ("th32ProcessID", ctypes.wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.wintypes.LPVOID),
        ("th32ModuleID", ctypes.wintypes.DWORD),
        ("cntThreads", ctypes.wintypes.DWORD),
        ("th32ParentProcessID", ctypes.wintypes.DWORD),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("szExeFile", ctypes.wintypes.CHAR * 260)]

class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.wintypes.DWORD),
        ("dwLocalAddr", ctypes.wintypes.DWORD),
        ("dwLocalPort", ctypes.wintypes.DWORD),
        ("dwRemoteAddr", ctypes.wintypes.DWORD),
        ("dwRemotePort", ctypes.wintypes.DWORD),
        ("dwOwningPid", ctypes.wintypes.DWORD)]

class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", ctypes.wintypes.DWORD),
        ("table", MIB_TCPROW_OWNER_PID * 1)]

class FILE_NOTIFY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset", ctypes.wintypes.DWORD),
        ("Action", ctypes.wintypes.DWORD),
        ("FileNameLength", ctypes.wintypes.DWORD),
        ("FileName", ctypes.wintypes.WCHAR * 1024)]

class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", ctypes.wintypes.DWORD),
        ("dwCurrentState", ctypes.wintypes.DWORD),
        ("dwControlsAccepted", ctypes.wintypes.DWORD),
        ("dwWin32ExitCode", ctypes.wintypes.DWORD),
        ("dwServiceSpecificExitCode", ctypes.wintypes.DWORD),
        ("dwCheckPoint", ctypes.wintypes.DWORD),
        ("dwWaitHint", ctypes.wintypes.DWORD),]

####################################################################################################

class MainWindow_Controller(QMainWindow):
    scan_progress_signal = Signal(str)
    scan_add_virus_signal = Signal(str)
    scan_result_signal = Signal(str)
    scan_reset_signal = Signal()
    progress_title_signal = Signal(str)

    def __init__(self):
        super().__init__()
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.init_environ()
        self.init_variable()
        self.load_config()
        self.init_interface()
        self.init_windll()
        self.backup_mbr()
        self.relock_file()
        self.init_whitelist()
        self.init_thread()
        self.init_connect()
        self.show_startup()

####################################################################################################

    def init_variable(self):
        self.ui = Ui_main_window()
        self.ui.setupUi(self)
        self.python = sys.executable
        self.process_timer = QTimer(self)

        self.model = model_scanner()
        self.model.load_path(self.path_models)
        self.rule = rule_scanner()
        self.rule.load_path(self.path_rules)

        self.mouse_flag = 0
        self.mouse_pos = 0
        self.current_opacity = 0

        self.scan_running = False
        self.virus_lock = {}
        self.virus_results = []
        self.scan_count = 0
        self.mbr_backup = {}

        self.theme_names = [
            "white_switch", "red_switch", "yellow_switch",
            "green_switch", "blue_switch", "black_switch",
        ]
        self.lang_names = [
            "traditional_switch", "simplified_switch", "english_switch",
        ]
        self.pyas_default = {
            "version": "3.3.4",
            "product": "00000-00000-00000-00000-00000",
            "language": "english_switch",
            "theme": "white_switch",
            "sensitive": 95,
            "process_switch": True,
            "document_switch": True,
            "system_switch": True,
            "driver_switch": True,
            "network_switch": True,
            "custom_rule": [],
        }
        self.pass_windows = [
            {"exe": "System Idle Process", "class": "", "title": ""},
            {"exe": "", "class": "Windows.UI.Core.CoreWindow", "title": ""},
            {"exe": "", "class": "Qt691QWindowIcon", "title": "PYAS"},
            {"exe": "explorer.exe", "class": "", "title": ""},
        ]
        self.block_replace = {
            "BOOT_BLOCK": "引導行為攔截",
            "REG_BLOCK": "註冊表行為攔截",
            "FILE_BLOCK": "檔案行為攔截",
            "RANSOM_BLOCK": "勒索行為攔截",
            "CLR_BLOCK": "托管行為攔截",
            "SHELLCODE_BLOCK": "殼碼行為攔截",
            "THREAD_BLOCK": "線程行為攔截",
            "INJECT_BLOCK": "注入行為攔截",
            "PROC_BLOCK": "進程行為攔截",
        }

####################################################################################################

    def init_environ(self):
        self.file_pyas = self.norm_path(sys.argv[0])
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
        self.path_models = os.path.join(self.path_pyas, "Engine", "Models")
        self.path_rules = os.path.join(self.path_pyas, "Engine", "Rules")
        self.path_protect = os.path.join(self.path_pyas, "Plugins", "Filter")
        self.path_drivers = os.path.join(self.path_protect, "PYAS_Driver.sys")

####################################################################################################

    def init_windll(self):
        for name in ["ntdll", "Psapi", "user32", "kernel32", "advapi32", "iphlpapi"]:
            try:
                setattr(self, name.lower(), ctypes.WinDLL(name, use_last_error=True))
            except Exception as e:
                self.send_message(e, "warn", False)

        self.advapi32.OpenSCManagerW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.wintypes.DWORD]
        self.advapi32.OpenSCManagerW.restype = ctypes.wintypes.HANDLE

        self.advapi32.CreateServiceW.argtypes = [
            ctypes.wintypes.HANDLE, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.c_wchar_p,
            ctypes.c_wchar_p, ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.c_wchar_p, ctypes.c_wchar_p,
            ctypes.c_wchar_p
        ]
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

####################################################################################################

    def save_config(self, file_path, config):
        try:
            filter_config = {}
            for k, v in config.items():
                if k.endswith("_button") and isinstance(v, bool) and k.replace("_button", "_window") in self.widgets:
                    continue
                filter_config[k] = v
            path = os.path.dirname(file_path)
            if not os.path.exists(path):
                os.makedirs(path)
            with open(file_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(json.dumps(filter_config, indent=4, ensure_ascii=False))
        except Exception as e:
            self.send_message(e, "warn", False)

    def read_config(self, file_path, default_value):
        try:
            config_value = {}
            if os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    config_value = json.load(f)
            for key, value in default_value.items():
                config_value.setdefault(key, value)
            return config_value
        except Exception as e:
            self.send_message(e, "warn", False)
            return default_value.copy()

    def load_config(self):
        existed = os.path.exists(self.file_config)
        self.pyas_config = self.read_config(self.file_config, self.pyas_default)
        if existed:
            dv = str(self.pyas_default.get("version", "")).strip()
            cv = str(self.pyas_config.get("version", "")).strip()
            if dv and dv != cv:
                self.pyas_config["version"] = dv
                self.save_config(self.file_config, self.pyas_config)

    def config_list(self, key):
        if key not in self.pyas_config:
            self.pyas_config[key] = []
        return self.pyas_config[key]

####################################################################################################

    def init_interface(self):
        self.widgets = {k: v for k, v in self.ui.__dict__.items() if isinstance(v, QWidget)}

        self.menu_window = [self.widgets.get(x) for x in ["options_window", "navigate_window"]]
        self.sub_window = [self.widgets.get(x) for x in ["method_window", "solve_button"]]
        self.blank_window = [self.widgets.get("blank_window")]
        self.main_window = [self.widgets.get(x) for x in [
            "about_window", "setting_window", "protect_window",
            "taskmgr_window", "tool_window", "scan_window", "home_window"]]

        for w in self.sub_window:
            if w: w.hide()
        for w in self.main_window + self.menu_window:
            if w: w.raise_()
        for w in self.menu_window + self.blank_window:
            if w: w.setGraphicsEffect(self.create_shadow())

        self.last_widget = self.widgets.get("home_window")
        self.setup_theme_mapping()
        self.setup_process_menu()

    def create_shadow(self):
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setOffset(0, 0)
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(175, 175, 175))
        return shadow

####################################################################################################

    def init_connect(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(r":/icon/logo_black.png"))
        self.tray_icon.activated.connect(self.show_button)
        self.tray_icon.show()

        self.scan_progress_signal.connect(self.slot_scan_progress)
        self.scan_add_virus_signal.connect(self.slot_scan_add_virus)
        self.scan_result_signal.connect(self.slot_scan_result)
        self.scan_reset_signal.connect(self.slot_scan_reset)
        self.progress_title_signal.connect(self.slot_progress_title)

        for name, widget in self.widgets.items():
            if hasattr(widget, "setCheckable") and widget.isCheckable():
                if name in self.lang_names:
                    widget.toggled.connect(lambda checked, ln=name: self.on_language_radio(ln, checked))
                    if self.pyas_config.get("language") == name:
                        widget.setChecked(True)
                elif name in self.theme_names:
                    widget.toggled.connect(lambda checked, tn=name: self.on_theme_radio(tn, checked))
                    if self.pyas_config.get("theme") == name:
                        widget.setChecked(True)
                elif "_switch" in name:
                    widget.toggled.connect(lambda checked, n=name: self.save_state(n, checked))
                    if name in self.pyas_config:
                        try:
                            widget.setChecked(self.pyas_config[name])
                        except Exception:
                            pass

            if "_button" in name and hasattr(widget, "clicked"):
                wn = name.replace("_button", "_window")
                if self.widgets.get(wn):
                    widget.clicked.connect(lambda _, wn=wn: self.change_window(wn))
                elif hasattr(self, name):
                    widget.clicked.connect(getattr(self, name))

    def on_language_radio(self, ln, checked):
        if checked:
            self.pyas_config["language"] = ln
            self.save_config(self.file_config, self.pyas_config)
            self.apply_settings()

    def on_theme_radio(self, tn, checked):
        if checked:
            self.pyas_config["theme"] = tn
            self.save_config(self.file_config, self.pyas_config)
            self.apply_settings()

####################################################################################################

    def save_state(self, name, checked):
        self.pyas_config[name] = bool(checked)
        if name == "sensitive_switch":
            self.pyas_config["sensitive"] = 0 if checked else 95
        elif name == "extension_switch":
            pass
        elif name == "process_switch":
            if checked:
                self.start_daemon_thread(self.protect_proc_thread)
        elif name == "document_switch":
            if checked:
                self.start_daemon_thread(self.protect_file_thread)
        elif name == "system_switch":
            if checked:
                self.start_daemon_thread(self.protect_system_thread)
        elif name == "driver_switch":
            if not checked:
                self.stop_system_driver()
            elif self.install_system_driver():
                self.start_daemon_thread(self.pipe_server_thread)
            else:
                self.send_message("驅動防護啟用失敗", "warn", True)
        elif name == "network_switch":
            if checked:
                self.start_daemon_thread(self.protect_net_thread)
        else:
            self.send_message(f"此功能不支持使用", "info", True)
        self.save_config(self.file_config, self.pyas_config)

    def init_thread(self):
        self.start_daemon_thread(self.popup_intercept_thread)

    def start_daemon_thread(self, target, *args, **kwargs):
        t = threading.Thread(target=target, args=args, kwargs=kwargs, daemon=True)
        t.start()
        return t

####################################################################################################

    def setup_theme_mapping(self):
        for name, widget in self.widgets.items():
            mapping = {}
            base_name = name.replace("_button", "").replace("_window", "")
            theme_icon_map = {
                theme: f":/icon/{base_name}_{'white' if theme == 'black_switch' else 'black'}.png"
                for theme in self.theme_names}

            if hasattr(widget, "setPixmap"):
                mapping["pixmap"] = theme_icon_map
            if hasattr(widget, "setIcon"):
                mapping["icon"] = theme_icon_map
            if mapping:
                widget._theme_mapping = mapping

####################################################################################################

    def apply_settings(self):
        lang = self.pyas_config.get("language", "english_switch")
        theme = self.pyas_config.get("theme", "white_switch")
        lang_map = translate_dict.get(lang, {})
        theme_map = translate_dict.get(theme, {})

        for name, widget in self.widgets.items():
            if "_switch" in name and hasattr(widget, "setText") and hasattr(widget, "isChecked"):
                if name not in self.lang_names + self.theme_names:
                    checked = widget.isChecked()
                    widget.setText(lang_map.get("開啟", "開啟") if checked else lang_map.get("關閉", "關閉"))

                    if not widget.property("_connected_toggle"):
                        widget.toggled.connect(lambda checked, b=widget: self.toggle_switch_text(b, checked))
                        widget.setProperty("_connected_toggle", True)
                else:
                    if not hasattr(widget, "_origin_text"):
                        widget._origin_text = self.get_widget_text(widget)
                    widget.setText(self.trans(lang, widget._origin_text))

            elif hasattr(widget, "setText"):
                if name in ["log_text","license_text"]:
                    pass
                else:
                    if not hasattr(widget, "_origin_text"):
                        widget._origin_text = self.get_widget_text(widget)
                    widget.setText(self.trans(lang, widget._origin_text))

            if hasattr(widget, "setStyleSheet"):
                if not hasattr(widget, "_origin_style"):
                    widget._origin_style = widget.styleSheet()
                style = widget._origin_style
                for k, v in theme_map.items():
                    style = style.replace(str(k), str(v))
                widget.setStyleSheet(style)

            mapping = getattr(widget, "_theme_mapping", None)
            if isinstance(mapping, dict):
                if "icon" in mapping and hasattr(widget, "setIcon"):
                    icon_path = mapping["icon"].get(theme)
                    if icon_path and (os.path.exists(icon_path) or icon_path.startswith(":")):
                        widget.setIcon(QIcon(icon_path))
                        widget.icon_path = icon_path

                if "pixmap" in mapping and hasattr(widget, "setPixmap"):
                    pm_path = mapping["pixmap"].get(theme)
                    if pm_path and pm_path.startswith(":"):
                        pix = QPixmap(pm_path)
                        if not pix.isNull():
                            widget.setPixmap(pix)
                            widget.pixmap_path = pm_path

####################################################################################################

    def toggle_switch_text(self, btn, checked):
        lang = self.pyas_config.get("language", "traditional_switch")
        switch_map = translate_dict.get(lang, {})
        btn.setText(switch_map.get("開啟", "開啟") if checked else switch_map.get("關閉", "關閉"))

    def get_widget_text(self, widget):
        for method in ["text", "toPlainText", "currentText"]:
            if hasattr(widget, method) and callable(getattr(widget, method)):
                return getattr(widget, method)()
        return ""

    def trans(self, language, text):
        for key, value in translate_dict.get(language, translate_dict).items():
            text = str(text).replace(str(key), str(value))
        return text.rstrip()

####################################################################################################

    def change_opacity(self, widget, current, target, duration=200):
        self.cleanup_animation(widget, "opacity_animation")
        anim = QPropertyAnimation(widget, b"windowOpacity")
        anim.setStartValue(current / 100.0)
        anim.setEndValue(target / 100.0)
        anim.setDuration(duration)
        anim.setEasingCurve(QEasingCurve.Linear)
        anim.valueChanged.connect(lambda v: self.update_opacity(widget, v))
        anim.start()
        widget.opacity_animation = anim

    def update_opacity(self, widget, value):
        widget.setWindowOpacity(value)
        widget.current_opacity = value * 100
        widget.setVisible(value > 0)

    def cleanup_animation(self, widget, attr):
        anim = getattr(widget, attr, None)
        if anim:
            anim.stop()
            anim.deleteLater()
            setattr(widget, attr, None)

####################################################################################################

    def change_window(self, widget_name, duration=200):
        widget = self.widgets.get(widget_name)
        if widget and widget != self.last_widget:
            widget.raise_()
            widget.hide()
            for window in self.menu_window:
                window.raise_()
            for window in self.sub_window:
                window.hide()
            self.animate_geometry(widget, duration)
            self.last_widget = widget

            if widget_name == "taskmgr_window":
                self.start_process_timer()
            else:
                self.stop_process_timer()

    def animate_geometry(self, widget, duration):
        click = widget.mapFromGlobal(QCursor.pos())
        w, h = widget.width(), widget.height()
        final_radius = int(((max(click.x(), w - click.x())) ** 2 + (max(click.y(), h - click.y())) ** 2) ** 0.5)
        anim = QVariantAnimation(widget)
        anim.setStartValue(0)
        anim.setEndValue(final_radius)
        anim.setDuration(duration)
        anim.valueChanged.connect(lambda val: self.update_geometry(widget, click, val))
        anim.start()

    def update_geometry(self, widget, click, value):
        widget.setMask(QRegion(click.x() - value, click.y() - value, 2 * value, 2 * value, QRegion.Ellipse))
        widget.setVisible(value > 0)

####################################################################################################

    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            self.mouse_flag = True
            self.mouse_pos = event.globalPosition().toPoint() - self.pos()
            self.change_opacity(self, self.current_opacity, 80, 100)
            event.accept()

    def mouseMoveEvent(self, event: QMouseEvent):
        if self.mouse_flag:
            new_top_left = event.globalPosition().toPoint() - self.mouse_pos
            self.move(new_top_left)
            event.accept()

    def mouseReleaseEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton and self.mouse_flag:
            self.mouse_flag = False
            self.setCursor(QCursor(Qt.ArrowCursor))
            self.change_opacity(self, self.current_opacity, 100, 100)
            event.accept()

####################################################################################################

    def nativeEvent(self, eventType, message):
        event = ctypes.wintypes.MSG.from_address(int(message))
        if event.message in [0x0010, 0x0002, 0x0012, 0x0112, 0x0212]:
            return True, 0
        return super().nativeEvent(eventType, message)

    def show_startup(self):
        try:
            if self.singleton_mutex("pyas_security"):
                param = ""
                if self.args_pyas:
                    param = self.args_pyas[0].replace("/", "-")
                if "-h" not in param:
                    self.show_button()
                self.apply_settings()
            else:
                sys.exit(0)
        except Exception as e:
            self.send_message(e, "warn", False)

    def show_button(self):
        self.show()
        self.activateWindow()
        self.repaint()
        self.change_opacity(self, self.current_opacity, 100, 200)

    def minimize_button(self):
        self.change_opacity(self, self.current_opacity, 0, 200)

    def close_button(self):
        if self.send_message("您確定要退出所有防護嗎?", "quest", True):
            self.pyas_config["process_switch"] = False
            self.pyas_config["document_switch"] = False
            self.pyas_config["system_switch"] = False
            self.pyas_config["driver_switch"] = False
            self.pyas_config["network_switch"] = False
            self.stop_system_driver()

            self.minimize_button()
            while self.isVisible():
                QApplication.processEvents()
            if hasattr(self, "tray_icon"):
                self.tray_icon.hide()
                self.tray_icon.deleteLater()
            QApplication.quit()

    def reset_button(self):
        if self.send_message("您確定要重置所有設定嗎?", "quest", True):
            self.pyas_config = self.pyas_default.copy()
            self.restart_button()

    def restart_button(self):
        self.save_config(self.file_config, self.pyas_config)
        self.minimize_button()
        while self.isVisible():
            QApplication.processEvents()
        os.execl(self.python, self.python, *sys.argv)

    def singleton_mutex(self, name):
        mutex = self.kernel32.CreateMutexW(None, False, name)
        if self.kernel32.GetLastError() == 183:
            return False
        return True

####################################################################################################

    def send_message(self, message, mode, translate=True):
        if QThread.currentThread() != QApplication.instance().thread():
            QMetaObject.invokeMethod(self, "send_message_thread", Qt.QueuedConnection,
                Q_ARG("QString", str(message)), Q_ARG("QString", mode), Q_ARG("bool", translate))
            return False
        return self.send_message_thread(message, mode, translate)

    @Slot(str, str, bool)
    def send_message_thread(self, message, mode, translate=True):
        try:
            yes, no, ok = QMessageBox.Yes, QMessageBox.No, QMessageBox.Ok
            select = None

            if not isinstance(message, str):
                message = str(message)
            if message and translate:
                message = self.trans(self.pyas_config["language"], message)

            m = mode.lower()
            if m == "quest":
                select = QMessageBox.question(self, "Quest", message, yes | no) == yes
            elif m == "info":
                select = QMessageBox.information(self, "Info", message, ok) == ok
            elif m == "error":
                select = QMessageBox.critical(self, "Error", message, ok) == ok
            elif m == "notify":
                now = time.strftime("%Y-%m-%d %H:%M:%S")
                self.tray_icon.showMessage(now, message, QSystemTrayIcon.Information, 5000)
            elif m == "files":
                select = QFileDialog.getOpenFileNames(self, message)[0]
            elif m == "file":
                select = QFileDialog.getOpenFileName(self, message)[0]
            elif m == "path":
                select = QFileDialog.getExistingDirectory(self, message)
            elif m == "save":
                select = QFileDialog.getSaveFileName(self, message)[0]

            select = select or False
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            output = f"[{now}] | {mode} | {message} | {select}"
            log_widget = self.widgets.get("log_text")
            if log_widget:
                log_widget.append(output)
            return select
        except Exception:
            traceback.print_exc()
            return False

    def invoke_method(self, obj, method, *args):
        q_args = []
        for arg in args:
            if isinstance(arg, int):
                q_args.append(Q_ARG("int", arg))
            elif isinstance(arg, QSystemTrayIcon.MessageIcon):
                q_args.append(Q_ARG("QSystemTrayIcon::MessageIcon", arg))
            else:
                q_args.append(Q_ARG("QString", str(arg)))
        QMetaObject.invokeMethod(obj, method, Qt.QueuedConnection, *q_args)

    def norm_path(self, path):
        if isinstance(path, (list, tuple, set)):
            t = type(path)
            return t(self.norm_path(p) for p in path)
        if isinstance(path, str):
            return os.path.normpath(os.path.abspath(path))
        return path

####################################################################################################

    @Slot()
    def slot_scan_reset(self):
        self.widgets["virus_list"].clear()
        self.widgets["solve_button"].hide()
        self.widgets["stop_button"].show()
        self.widgets["method_button"].hide()
        self.widgets["method_window"].hide()

    @Slot(str)
    def slot_progress_title(self, text: str):
        self.widgets["progress_title"].setText(text)

    @Slot(str)
    def slot_scan_progress(self, text):
        self.widgets["progress_text"].setText(text)

    @Slot(str)
    def slot_scan_add_virus(self, item_text):
        item = QListWidgetItem(item_text)
        item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
        item.setCheckState(Qt.Checked)
        self.widgets["virus_list"].addItem(item)

    @Slot(str)
    def slot_scan_result(self, msg):
        self.widgets["progress_text"].setText(msg)
        count = len(self.virus_results)
        self.widgets["solve_button"].setVisible(count > 0)
        self.widgets["stop_button"].hide()
        self.widgets["method_button"].show()
        self.send_message(msg, "notify", True)

####################################################################################################

    def init_scan(self):
        try:
            self.scan_running = True
            self.virus_results = []
            self.scan_count = 0
            self.scan_start = time.time()
            self.last_widget = self.widgets.get("scan_window")
            self.scan_reset_signal.emit()
            self.progress_title_signal.emit(self.trans(self.pyas_config["language"], "正在掃描"))
            self.scan_progress_signal.emit(self.trans(self.pyas_config["language"], "正在初始化中"))
        except Exception as e:
            self.send_message(e, "warn", False)

    def file_button(self):
        targets = self.send_message("檔案掃描", "files", True)
        if targets:
            self.init_scan()
            self.start_daemon_thread(self.scan_worker, targets)

    def path_button(self):
        targets = self.send_message("路徑掃描", "path", True)
        if targets:
            self.init_scan()
            self.start_daemon_thread(self.scan_worker, targets)

    def full_button(self):
        targets = [f"{chr(d)}:/" for d in range(65, 91) if os.path.exists(f"{chr(d)}:/")]
        if targets:
            self.init_scan()
            self.start_daemon_thread(self.scan_worker, targets)

####################################################################################################

    def scan_worker(self, targets):
        try:
            for file_path in self.yield_files(targets):
                if not self.scan_running:
                    break
                try:
                    norm_path = self.norm_path(file_path)
                    if self.is_in_whitelist(norm_path):
                        continue
                    self.scan_count += 1
                    state = self.scan_engine(norm_path)
                    if state:
                        self.virus_results.append(norm_path)
                        self.scan_add_virus_signal.emit(f"[{state}] > {norm_path}")
                    self.scan_progress_signal.emit(norm_path)
                except Exception as e:
                    self.send_message(e, "warn", False)
        finally:
            elapsed = int(time.time() - self.scan_start)
            count = len(self.virus_results)
            result = (
                f"發現 {count} 個病毒，耗時 {elapsed} 秒，共掃描 {self.scan_count} 檔案"
                if count else f"未發現病毒，耗時 {elapsed} 秒，共掃描 {self.scan_count} 檔案")
            self.progress_title_signal.emit(self.trans(self.pyas_config["language"], "病毒掃描"))
            self.scan_result_signal.emit(self.trans(self.pyas_config["language"], result))

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
        try:
            label, level = self.model.model_scan(file_path)
            if label and level >= self.pyas_config.get("sensitive", 95):
                return f"{label}.{level}"

            if self.pyas_config.get("extension_switch", False):
                label, level = self.rule.yara_scan(file_path)
                if label and level:
                    return f"{label}.{level}"
        except Exception as e:
            self.send_message(e, "warn", False)
        return None

####################################################################################################

    def solve_button(self):
        deleted = 0
        virus_list = self.widgets["virus_list"]
        for i in reversed(range(virus_list.count())):
            item = virus_list.item(i)
            if item.checkState() == Qt.Checked:
                try:
                    file_path = self.norm_path(item.text().split(">")[1].strip())
                    os.remove(file_path)
                    deleted += 1
                except Exception as e:
                    self.send_message(e, "warn", False)
                virus_list.takeItem(i)
        self.widgets["solve_button"].hide()
        msg = f"已清理 {deleted} 個病毒檔案" if deleted else "無檔案被刪除"
        self.widgets["progress_text"].setText(self.trans(self.pyas_config["language"], msg))

    def stop_button(self):
        self.scan_running = False
        self.widgets["stop_button"].hide()

####################################################################################################

    def list_process(self):
        pe = self.get_process_entry()
        snapshot = self.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        result, success = [], self.kernel32.Process32First(snapshot, ctypes.byref(pe))
        while success:
            pid = pe.th32ProcessID
            name, file_path = (None, None)
            if pid > 4:
                name, file_path = self.get_exe_info(pid)
            if not name:
                raw = bytes(pe.szExeFile).split(b"\x00", 1)[0]
                if raw:
                    try:
                        name = raw.decode("mbcs", errors="replace") or None
                    except Exception:
                        name = None
            result.append((pid, name, file_path))
            success = self.kernel32.Process32Next(snapshot, ctypes.byref(pe))
        self.kernel32.CloseHandle(snapshot)
        return result

    def refresh_process(self):
        procs = self.list_process()
        self.proc_pid_map = [pid for pid, _, _ in procs]
        widget = self.widgets.get("manage_list")
        info_text = self.widgets.get("info_text")
        if widget:
            model = QStringListModel([f"{name or 'None'} | {pid} | {file_path or 'None'}" for pid, name, file_path in procs])
            widget.setModel(model)
        if info_text:
            info_text.setText(str(len(self.proc_pid_map)))

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

    def start_process_timer(self):
        if hasattr(self, "process_timer") and self.process_timer.isActive():
            return
        self.process_timer = QTimer(self)
        self.process_timer.timeout.connect(self.refresh_process)
        self.process_timer.start(0)

    def stop_process_timer(self):
        if hasattr(self, "process_timer"):
            self.process_timer.stop()

    def setup_process_menu(self):
        widget = self.widgets.get("manage_list")
        if widget:
            widget.setContextMenuPolicy(Qt.CustomContextMenu)
            widget.customContextMenuRequested.connect(self.show_process_menu)

    def show_process_menu(self, pos):
        widget = self.widgets.get("manage_list")
        if not widget:
            return
        idx = widget.indexAt(pos)
        if not idx.isValid() or idx.row() >= len(self.proc_pid_map):
            return
        pid = self.proc_pid_map[idx.row()]
        menu = QMenu()
        kill_action = menu.addAction("結束進程")
        if menu.exec(widget.viewport().mapToGlobal(pos)) == kill_action:
            self.kill_process(pid)

    def kill_process(self, pid):
        try:
            h = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if h:
                file_path = self.norm_path(self.get_process_file(h))
                if hasattr(self, "file_pyas") and file_path == getattr(self, "file_pyas", None):
                    self.close()
                else:
                    self.kernel32.TerminateProcess(h, 0)
                self.kernel32.CloseHandle(h)
        except Exception as e:
            self.send_message(e, "warn", False)
        self.refresh_process()

####################################################################################################

    def clean_button(self):
        try:
            if self.send_message("您確定要清理系統垃圾嗎?", "quest", True):
                self.total_deleted_size = 0
                for path in [self.path_temp, self.path_systemp]:
                    self.traverse_temp(path)
                size_text = self.format_size(self.total_deleted_size)
                self.send_message(f"成功清理了 {size_text} 系統垃圾", "info", True)
        except Exception as e:
            self.send_message(e, "warn", False)

    def traverse_temp(self, path):
        try:
            if not os.path.exists(path):
                return
            for fd in os.listdir(path):
                file = os.path.join(path, fd)
                try:
                    QApplication.processEvents()
                    if os.path.isdir(file):
                        self.traverse_temp(file)
                        try:
                            os.rmdir(file)
                        except Exception:
                            pass
                    else:
                        file_size = os.path.getsize(file)
                        os.remove(file)
                        self.total_deleted_size += file_size
                except Exception:
                    continue
        except Exception as e:
            self.send_message(e, "warn", False)

    def format_size(self, size):
        units = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
        for unit in units:
            if size < 1024 or unit == units[-1]:
                return f"{size:.2f} {unit}"
            size /= 1024

####################################################################################################

    def repair_button(self):
        try:
            if self.send_message("您確定要修復系統檔案嗎?", "quest", True):
                self.repair_system_mbr()
                self.repair_system_wallpaper()
                self.repair_system_restrict()
                self.repair_system_file_type()
                self.repair_system_file_icon()
                self.repair_system_image()
                self.send_message("修復系統檔案成功", "info", True)
        except Exception as e:
            self.send_message(e, "warn", False)

    def backup_mbr(self, max_drives=26):
        self.mbr_backup = {}
        for drive in range(max_drives):
            drive_path = rf"\\.\PhysicalDrive{drive}"
            try:
                with open(drive_path, "rb") as f:
                    mbr = f.read(512)
                if mbr[510:512] == b"\x55\xAA":
                    self.mbr_backup[drive] = mbr
            except FileNotFoundError:
                continue
            except PermissionError as e:
                continue
            except Exception as e:
                self.send_message(e, "warn", False)

    def repair_system_mbr(self):
        if not hasattr(self, "mbr_backup") or not self.mbr_backup:
            return
        for drive, mbr_value in self.mbr_backup.items():
            drive_path = rf"\\.\PhysicalDrive{drive}"
            try:
                with open(drive_path, "rb+") as f:
                    current = f.read(512)
                    if current != mbr_value:
                        f.seek(0)
                        f.write(mbr_value)
            except PermissionError as e:
                continue
            except Exception as e:
                self.send_message(e, "warn", False)

    def repair_system_wallpaper(self):
        try:
            wallpaper = os.path.join(self.path_system, "web", "wallpaper", "Windows", "img0.jpg")
            if not os.path.exists(wallpaper):
                return
            key = r"Control Panel\\Desktop"
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
            self.send_message(e, "warn", False)

    def repair_system_restrict(self):
        try:
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
            restrict_paths = [
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\MMC"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\Windows\System"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System"),
            ]

            for hkey, path in restrict_paths:
                try:
                    with winreg.OpenKey(hkey, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WRITE) as reg:
                        for value in permissions:
                            try:
                                winreg.DeleteValue(reg, value)
                            except FileNotFoundError:
                                continue
                except FileNotFoundError:
                    continue
        except Exception as e:
            self.send_message(e, "warn", False)

    def repair_system_file_type(self):
        try:
            file_types = [".exe", ".bat", ".cmd", ".com"]
            for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                for ext in file_types:
                    try:
                        with winreg.CreateKey(root, rf"SOFTWARE\Classes\{ext}") as reg:
                            winreg.SetValue(reg, "", winreg.REG_SZ, "exefile" if ext == ".exe" else ext[1:]+"file")
                    except Exception:
                        continue

                for shell_cmd in ["open", "runas"]:
                    try:
                        with winreg.CreateKey(root, r"SOFTWARE\Classes\exefile\shell\{}\command".format(shell_cmd)) as reg:
                            winreg.SetValue(reg, "", winreg.REG_SZ, '"%1" %*')
                    except Exception:
                        continue
        except Exception as e:
            self.send_message(e, "warn", False)

    def repair_system_file_icon(self):
        try:
            for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                try:
                    with winreg.CreateKey(root, r"SOFTWARE\Classes\exefile\DefaultIcon") as reg:
                        winreg.SetValue(reg, "", winreg.REG_SZ, "%1")
                except Exception:
                    continue
        except Exception as e:
            self.send_message(e, "warn", False)

    def repair_system_image(self):
        try:
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS) as reg:
                i = 0
                while True:
                    try:
                        subkey = winreg.EnumKey(reg, i)
                        subkey_path = key_path + "\\" + subkey
                        with winreg.OpenKey(reg, subkey, 0, winreg.KEY_ALL_ACCESS) as sub_reg:
                            for value in ["Debugger", "UseFilter", "GlobalFlag", "MitigationOptions"]:
                                try:
                                    winreg.DeleteValue(sub_reg, value)
                                except FileNotFoundError:
                                    continue
                        i += 1
                    except OSError:
                        break
        except Exception as e:
            self.send_message(e, "warn", False)

####################################################################################################

    def popup_button(self):
        self.config_list("block_list")
        self.block_window = False
        if self.send_message("請選擇要攔截的軟體彈窗", "quest", True):
            while True:
                QApplication.processEvents()
                title, class_name, process_name = self.get_window_info(self.user32.GetForegroundWindow())
                if process_name and not any(self.window_rule_match(item, process_name, class_name, title) for item in self.pass_windows):
                    if self.send_message(f"您確定要攔截 {process_name} ({title}) 嗎?", "quest", True):
                        if self.add_window_rule(self.pyas_config["block_list"], process_name, class_name, title):
                            self.send_message(f"成功增加到彈窗攔截: {process_name} ({title})", "info", True)
                        else:
                            self.send_message("已存在彈窗攔截", "info", True)
                    break
        self.start_daemon_thread(self.popup_intercept_thread)

    def popup_button_2(self):
        self.config_list("block_list")
        self.block_window = False
        if self.send_message("請選擇要取消攔截的軟體彈窗", "quest", True):
            while True:
                QApplication.processEvents()
                title, class_name, process_name = self.get_window_info(self.user32.GetForegroundWindow())
                if process_name and not any(self.window_rule_match(item, process_name, class_name, title) for item in self.pass_windows):
                    if self.send_message(f"您確定要取消攔截 {process_name} ({title}) 嗎?", "quest", True):
                        if self.remove_window_rule(self.pyas_config["block_list"], process_name, class_name, title):
                            self.send_message(f"成功取消彈窗攔截: {process_name} ({title})", "info", True)
                        else:
                            self.send_message("未找到彈窗攔截", "info", True)
                    break
        self.start_daemon_thread(self.popup_intercept_thread)

    def window_rule_match(self, item, process_name, class_name, title):
        for k, v in zip(["exe", "class", "title"], [process_name, class_name, title]):
            if item.get(k, "") and item.get(k, "") != v:
                return False
        return True

    def add_window_rule(self, rule_list, process_name, class_name, title):
        if not any(self.window_rule_match(item, process_name, class_name, title) for item in rule_list):
            rule_list.append({"exe": process_name, "class": class_name, "title": title})
            self.save_config(self.file_config, self.pyas_config)
            return True
        return False

    def remove_window_rule(self, rule_list, process_name, class_name, title):
        before = len(rule_list)
        rule_list[:] = [item for item in rule_list if not self.window_rule_match(item, process_name, class_name, title)]
        if len(rule_list) < before:
            self.save_config(self.file_config, self.pyas_config)
            return True
        return False

    def popup_intercept_thread(self):
        self.block_window = True
        while self.block_window:
            try:
                time.sleep(0.2)
                rules = self.pyas_config.get("block_list", [])
                if not rules:
                    continue
                for hWnd in self.get_all_windows():
                    title, class_name, process_name = self.get_window_info(hWnd)
                    if (not any(self.window_rule_match(item, process_name, class_name, title) for item in self.pass_windows) and
                        any(self.window_rule_match(item, process_name, class_name, title) for item in rules)):
                        for msg in [0x0010, 0x0002, 0x0012, 0x0112]:
                            self.user32.SendMessageW(hWnd, msg, 0xF060, 0)
            except Exception as e:
                self.send_message(e, "warn", False)

####################################################################################################

    def get_all_windows(self):
        self.hwnd_list = []
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
        self.user32.EnumWindows(WNDENUMPROC(self.enum_windows_callback), 0)
        return self.hwnd_list

    def enum_windows_callback(self, hWnd, lParam):
        self.hwnd_list.append(hWnd)
        return True

    def get_window_info(self, hWnd):
        length = self.user32.GetWindowTextLengthW(hWnd)
        title = ctypes.create_unicode_buffer(length + 1)
        self.user32.GetWindowTextW(hWnd, title, length + 1)
        class_name = ctypes.create_unicode_buffer(256)
        self.user32.GetClassNameW(hWnd, class_name, 256)
        pid = ctypes.c_ulong()
        self.user32.GetWindowThreadProcessId(hWnd, ctypes.byref(pid))
        process_name = ""
        try:
            process_name = self.get_process_name_by_pid(pid.value)
        except Exception:
            pass
        return str(title.value), str(class_name.value), process_name

    def get_process_name_by_pid(self, pid):
        snapshot = self.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        name = ""
        if self.kernel32.Process32First(snapshot, ctypes.byref(entry)):
            while True:
                if entry.th32ProcessID == pid:
                    name = entry.szExeFile.decode("mbcs").rstrip("\x00")
                    break
                if not self.kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                    break
        self.kernel32.CloseHandle(snapshot)
        return name

####################################################################################################

    def whitelist_button(self):
        self.config_list("white_list")
        files = self.send_message("選擇檔案", "files", True)
        if files:
            if self.send_message("您確定要增加到白名單嗎?", "quest"):
                n = self.manage_named_list("white_list", files, action="add", with_hash=True)
                self.send_message(f"成功增加到白名單，共 {n} 個檔案", "info")

    def whitelist_button_2(self):
        self.config_list("white_list")
        files = self.send_message("選擇檔案", "files", True)
        if files:
            if self.send_message("您確定要移除白名單嗎?", "quest"):
                n = self.manage_named_list("white_list", files, action="remove", with_hash=True)
                self.send_message(f"成功移除白名單，共 {n} 個檔案", "info")

    def quarantine_button(self):
        self.config_list("quarantine")
        files = self.send_message("選擇檔案", "files", True)
        if files:
            if self.send_message("您確定要增加到隔離區嗎?", "quest"):
                n = self.manage_named_list("quarantine", files, action="add", with_hash=True, lock_func=self.lock_file)
                if n > 0:
                    self.send_message(f"成功增加到隔離區，共 {n} 個檔案", "info")

    def quarantine_button_2(self):
        self.config_list("quarantine")
        quarantine_dir = os.path.join(self.path_config, "quarantine")
        files = self.send_message("選擇檔案", "files", True)
        if files:
            if self.send_message("您確定要移除隔離區嗎?", "quest"):
                n = self.manage_named_list("quarantine", files, action="remove", with_hash=True, lock_func=self.lock_file)
                self.send_message(f"成功移除隔離區，共 {n} 個檔案", "info")

    def add_to_quarantine(self, files):
        self.config_list("quarantine")
        return self.manage_named_list("quarantine", files, action="add", with_hash=True, lock_func=self.lock_file)

    def is_in_whitelist(self, file_path):
        norm_path = self.norm_path(file_path)
        file_hash = self.calc_file_hash(norm_path)
        return any(item["file"] == norm_path and item["hash"] == file_hash
            for item in self.pyas_config.get("white_list", []))

    def init_whitelist(self):
        self.manage_named_list("white_list", [self.file_pyas], action="add", with_hash=True)

####################################################################################################

    def manage_named_list(self, list_key, files, action="add", with_hash=True, lock_func=None):
        target_list = self.config_list(list_key)
        files = files or []
        norm_paths = self.norm_path(files)
        if isinstance(norm_paths, str):
            norm_paths = [norm_paths]

        n = 0
        if action == "add":
            for path in norm_paths:
                QApplication.processEvents()
                file_hash = self.calc_file_hash(path) if with_hash else ""
                if not any(self.norm_path(item["file"]) == path and (not with_hash or item.get("hash", "") == file_hash) for item in target_list):
                    if lock_func:
                        try:
                            lock_func(path, True)
                        except Exception as e:
                            self.send_message(e, "warn", False)
                    target_list.append({"file": path, "hash": file_hash})
                    n += 1

        elif action == "remove":
            remove_list = [item for item in target_list if item["file"] in norm_paths]
            for item in remove_list:
                try:
                    if lock_func:
                        lock_func(item["file"], False)
                    target_list.remove(item)
                    n += 1
                except Exception as e:
                    self.send_message(e, "warn", False)
        if n:
            self.save_config(self.file_config, self.pyas_config)
        return n

    def calc_file_hash(self, file_path, block_size=65536):
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(block_size), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

####################################################################################################

    def website_button(self):
        try:
            webbrowser.open("https://github.com/87owo/PYAS")
            return True
        except Exception as e:
            self.send_message(e, "warn", False)
            return False

    def update_button(self):
        try:
            webbrowser.open("https://github.com/87owo/PYAS/releases")
            return True
        except Exception as e:
            self.send_message(e, "warn", False)
            return False

    def update_button(self):
        try:
            current = str(self.pyas_config.get("version", "")).strip()
            page = "https://github.com/87owo/PYAS/releases"
            latest = ""
            try:
                j = requests.get("https://api.github.com/repos/87owo/PYAS/releases/latest", headers={"Accept": "application/vnd.github+json", "User-Agent": "PYAS"}, timeout=10).json()
                latest = (j.get("tag_name") or j.get("name") or "").strip()
                page = j.get("html_url") or page
            except Exception:
                try:
                    u = requests.get("https://github.com/87owo/PYAS/releases/latest", headers={"User-Agent": "PYAS"}, allow_redirects=True, timeout=10).url
                    page = u or page
                    m = re.search(r"/tag/([^/]+)$", str(u))
                    latest = m.group(1).strip() if m else ""
                except Exception:
                    pass

            rl = re.sub(r"^[vV]\s*", "", str(latest))
            cl = re.sub(r"^[vV]\s*", "", str(current))
            tr = tuple(int(x) for x in re.findall(r"\d+", rl))
            tl = tuple(int(x) for x in re.findall(r"\d+", cl))
            if tr and (not tl or tr > tl):
                if self.send_message(f"發現新版本 {latest}，您確定要前往更新嗎?", "quest", True):
                    webbrowser.open(page)
            else:
                if cl:
                    self.send_message(f"當前已是最新版本 {current}", "info", True)
                else:
                    webbrowser.open(page)
            return True
        except Exception as e:
            self.send_message(e, "warn", False)
            return False

####################################################################################################

    def lock_file(self, file, lock):
        try:
            if lock:
                if file not in self.virus_lock:
                    self.virus_lock[file] = os.open(file, os.O_RDWR)
                msvcrt.locking(self.virus_lock[file], msvcrt.LK_NBRLCK, os.path.getsize(file))
            else:
                if file in self.virus_lock:
                    msvcrt.locking(self.virus_lock[file], msvcrt.LK_UNLCK, os.path.getsize(file))
                    os.close(self.virus_lock[file])
                    del self.virus_lock[file]
        except Exception as e:
            self.send_message(e, "warn", False)

    def relock_file(self):
        quarantine_list = self.pyas_config.get("quarantine", [])
        for item in quarantine_list:
            file = item["file"]
            if os.path.exists(file):
                try:
                    self.lock_file(file, True)
                except Exception as e:
                    self.send_message(e, "warn", False)

####################################################################################################

    def protect_proc_thread(self):
        self.exist_process = self.get_process_list()
        while self.pyas_config.get("process_switch", False):
            try:
                time.sleep(0.2)
                cur = self.get_process_list()
                for pid in cur - self.exist_process:
                    self.handle_new_process(pid)
                self.exist_process = cur
            except Exception as e:
                self.send_message(e, "warn", False)

    def get_process_list(self):
        exist_process, pe = set(), self.get_process_entry()
        hSnapshot = self.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        if self.kernel32.Process32First(hSnapshot, ctypes.byref(pe)):
            while True:
                exist_process.add(pe.th32ProcessID)
                if not self.kernel32.Process32Next(hSnapshot, ctypes.byref(pe)):
                    break
        self.kernel32.CloseHandle(hSnapshot)
        return exist_process

    def handle_new_process(self, pid):
        try:
            h = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if not h:
                return
            file_path = self.norm_path(self.get_process_file(h))
            if file_path and os.path.exists(file_path) and not self.is_in_whitelist(file_path):
                self.suspend_process(h, True)
                state = self.scan_engine(file_path)
                if state:
                    self.kernel32.TerminateProcess(h, 0)
                    self.send_message(f"進程防護 | 靜態掃描攔截 | {pid} | {file_path} | None", "notify", True)
                self.suspend_process(h, False)
            self.kernel32.CloseHandle(h)
        except Exception as e:
            self.send_message(e, "warn", False)

    def suspend_process(self, h_process, suspend):
        try:
            if not hasattr(self.ntdll, "NtSuspendProcess"):
                self.ntdll.NtSuspendProcess.argtypes = [ctypes.c_void_p]
                self.ntdll.NtSuspendProcess.restype = ctypes.c_ulong
                self.ntdll.NtResumeProcess.argtypes = [ctypes.c_void_p]
                self.ntdll.NtResumeProcess.restype = ctypes.c_ulong
            if suspend:
                self.ntdll.NtSuspendProcess(h_process)
            else:
                self.ntdll.NtResumeProcess(h_process)
        except Exception as e:
            self.send_message(e, "warn", False)

    def get_process_file(self, h_process):
        buf = ctypes.create_unicode_buffer(1024)
        if self.psapi.GetProcessImageFileNameW(h_process, buf, 1024):
            return self.norm_path(self.device_path_to_drive(buf.value))
        return ""

    def get_process_entry(self):
        pe = PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
        return pe

    def get_exe_info(self, pid):
        name, file_path = None, None
        h = self.kernel32.OpenProcess(0x1000, False, pid)
        if h:
            buf = ctypes.create_unicode_buffer(1024)
            if self.psapi.GetProcessImageFileNameW(h, buf, 1024):
                path = self.norm_path(self.device_path_to_drive(buf.value))
                if path:
                    file_path = path
                    name = os.path.basename(path)
            self.kernel32.CloseHandle(h)
        return name, file_path

####################################################################################################

    def protect_file_thread(self):
        hDir = self.kernel32.CreateFileW(self.path_user, 0x0001, 0x00000007, None, 3, 0x02000000, None)
        buffer = ctypes.create_string_buffer(65536)

        while self.pyas_config.get("document_switch", False):
            try:
                bytes_returned = ctypes.wintypes.DWORD()
                res = self.kernel32.ReadDirectoryChangesW(hDir, buffer, ctypes.sizeof(buffer), True,
                    0x0000001F, ctypes.byref(bytes_returned), None, None)

                if res:
                    notify = FILE_NOTIFY_INFORMATION.from_buffer_copy(buffer)
                    raw_filename = notify.FileName[:notify.FileNameLength // 2]
                    file_path = self.norm_path(os.path.join(self.path_user, raw_filename))

                    if notify.Action in [2, 3, 4] and not self.is_in_whitelist(file_path):
                        state = self.scan_engine(file_path)
                        if state:
                            self.add_to_quarantine([file_path])
                            self.send_message(f"檔案防護 | 靜態掃描攔截 | None | {file_path} | None", "notify", True)
            except Exception as e:
                self.send_message(e, "warn", False)
        self.kernel32.CloseHandle(hDir)

####################################################################################################

    def protect_net_thread(self):
        while self.pyas_config.get("network_switch", False):
            try:
                time.sleep(0.5)
                conns = self.get_connections_list()
                if not hasattr(self, "exist_connections") or self.exist_connections is None:
                    self.exist_connections = set()
                if conns is None:
                    conns = set()

                for key in conns - self.exist_connections:
                    self.handle_new_connection(key)
                self.exist_connections = conns
            except Exception as e:
                self.send_message(e, "warn", False)
        self.exist_connections = set()

    def get_connections_list(self):
        try:
            connections = set()
            size = ctypes.wintypes.DWORD()
            ret = self.iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), True, 2, 5, 0)
            if ret != 122:
                raise ctypes.WinError(ret)

            buf = ctypes.create_string_buffer(size.value)
            ret = self.iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), True, 2, 5, 0)
            if ret != 0:
                raise ctypes.WinError(ret)

            num_entries = ctypes.cast(buf, ctypes.POINTER(ctypes.wintypes.DWORD)).contents.value
            row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
            offset = ctypes.sizeof(ctypes.wintypes.DWORD)

            for i in range(num_entries):
                entry_addr = ctypes.addressof(buf) + offset + i * row_size
                row = MIB_TCPROW_OWNER_PID.from_address(entry_addr)
                connections.add((row.dwOwningPid, row.dwRemoteAddr, row.dwRemotePort))
            return connections
        except Exception as e:
            self.send_message(e, "warn", False)
            return set()

    def handle_new_connection(self, key):
        pid, remote_addr, remote_port = key
        try:
            h_process = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if not h_process:
                return
            file_path = self.norm_path(self.get_process_file(h_process))
            remote_ip = f"{remote_addr & 0xFF}.{(remote_addr >> 8) & 0xFF}.{(remote_addr >> 16) & 0xFF}.{(remote_addr >> 24) & 0xFF}"

            if file_path and os.path.exists(file_path) and not self.is_in_whitelist(file_path):
                if hasattr(self.rule, "network") and remote_ip in self.rule.network:
                    self.kernel32.TerminateProcess(h_process, 0)
                    self.send_message(f"網路防護 | 規則列表攔截 | {pid} | {file_path} | {remote_ip}", "notify", True)
            self.kernel32.CloseHandle(h_process)
        except Exception as e:
            self.send_message(e, "warn", False)

####################################################################################################

    def protect_system_thread(self):
        while self.pyas_config.get("system_switch", False):
            try:
                self.repair_system_mbr()
                self.repair_system_restrict()
                self.repair_system_file_type()
                self.repair_system_file_icon()
                self.repair_system_image()
                time.sleep(0.2)
            except Exception as e:
                self.send_message(e, "warn", False)

####################################################################################################

    def install_system_driver(self):
        service_name = "PYAS_Driver"
        scm = self.advapi32.OpenSCManagerW(None, None, 0xF003F)
        if not scm:
            return False

        svc = self.advapi32.CreateServiceW(scm, service_name, service_name, 0xF01FF, 
            0x00000001, 0x00000003, 0x00000001, self.path_drivers, None, None, None, None, None)
        if not svc:
            svc = self.advapi32.OpenServiceW(scm, service_name, 0xF01FF)
            if not svc:
                self.advapi32.CloseServiceHandle(scm)
                return False

        res = self.advapi32.StartServiceW(svc,0,None)
        self.advapi32.CloseServiceHandle(svc)
        self.advapi32.CloseServiceHandle(scm)
        return bool(res)

    def stop_system_driver(self):
        service_name = "PYAS_Driver"
        scm = self.advapi32.OpenSCManagerW(None, None, 0xF003F)
        if not scm:
            return False

        svc = self.advapi32.OpenServiceW(scm, service_name, 0xF01FF)
        if not svc:
            self.advapi32.CloseServiceHandle(scm)
            return False

        status = SERVICE_STATUS()
        self.advapi32.ControlService(svc, 0x00000001, ctypes.byref(status))
        self.advapi32.DeleteService(svc)
        self.advapi32.CloseServiceHandle(svc)
        self.advapi32.CloseServiceHandle(scm)
        return True

####################################################################################################

    def pipe_server_thread(self):
        pipe_path = r"\\.\pipe\PYAS_Output_Pipe"
        PIPE_BUF_SIZE = 65536

        while self.pyas_config.get("driver_switch", False):
            try:
                hPipe = self.kernel32.CreateNamedPipeW(pipe_path, 0x00000001, 0x00000004 | 0x00000002, 1, PIPE_BUF_SIZE, PIPE_BUF_SIZE, 0, None)
                if hPipe == ctypes.c_void_p(-1).value:
                    time.sleep(0.2)
                    continue

                while self.pyas_config.get("driver_switch", False):
                    if not self.kernel32.ConnectNamedPipe(hPipe, None) and self.kernel32.GetLastError() != 535:
                        time.sleep(0.2)
                        continue

                    buf = ctypes.create_string_buffer(PIPE_BUF_SIZE)
                    bytes_read = ctypes.c_ulong(0)
                    if not self.kernel32.ReadFile(hPipe, buf, PIPE_BUF_SIZE, ctypes.byref(bytes_read), None) or bytes_read.value == 0:
                        self.kernel32.DisconnectNamedPipe(hPipe)
                        time.sleep(0.2)
                        continue

                    msg = buf.raw[:bytes_read.value].decode("utf-8", errors="ignore")
                    parts = [p.strip() for p in msg.split("|", 3)]
                    if len(parts) == 4:
                        rules, pid, raw_path, target = parts
                        for old, new in self.block_replace.items():
                            rules = rules.replace(old, new)
                        self.send_message(f"驅動防護 | {rules} | {pid} | {raw_path} | {target}", "notify", True)

                    self.kernel32.DisconnectNamedPipe(hPipe)
                self.kernel32.CloseHandle(hPipe)
            except Exception as e:
                self.send_message(e, "warn", False)
                time.sleep(0.5)

####################################################################################################

if __name__ == "__main__":
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    MainWindow_Controller()
    sys.exit(app.exec())
