from PYAS_Diagnostics import log_exception
import os
import re
import io
import csv
import json
import time
import shutil
import threading
import sys
import pefile
import hashlib
import winreg
import requests
import subprocess
import ctypes
import ctypes.wintypes
from concurrent.futures import ThreadPoolExecutor
from PYAS_WinAPI import (
    COPYDATASTRUCT,
    ERROR_LOCK_VIOLATION,
    ERROR_NOT_FOUND,
    ERROR_OPERATION_ABORTED,
    ERROR_SHARING_VIOLATION,
    FILE_ATTRIBUTE_NORMAL,
    FILE_LOCK_RETRY_SECONDS,
    FILE_NOTIFY_INFORMATION,
    FILE_SCAN_DEBOUNCE_SECONDS,
    FILE_SCAN_RETRY_SECONDS,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILTER_MESSAGE_HEADER,
    FLT_PORT_FLAG_SYNC_HANDLE,
    GENERIC_READ,
    GUID,
    HRESULT_IO_PENDING,
    INTERNAL_STORAGE_BUS_TYPES,
    INVALID_HANDLE_VALUE,
    IOCTL_STORAGE_GET_HOTPLUG_INFO,
    IOCTL_STORAGE_QUERY_PROPERTY,
    IO_COUNTERS,
    LUID,
    LUID_AND_ATTRIBUTES,
    MEMORY_BASIC_INFORMATION,
    MIB_TCPROW_OWNER_PID,
    OPEN_EXISTING,
    OVERLAPPED,
    POINT,
    PROCESSENTRY32W,
    PROCESS_BASIC_INFORMATION,
    PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SUSPEND_RESUME,
    PROCESS_TERMINATE,
    PROCESS_VM_READ,
    PROPERTY_STANDARD_QUERY,
    PYAS_CONNECTION_CONTEXT,
    PYAS_CONNECTION_MAGIC,
    PYAS_CONNECTION_VERSION,
    PYAS_FULL_MESSAGE,
    PYAS_MESSAGE,
    PYAS_PROCESS_NETWORK_ACCESS,
    PYAS_PROCESS_SCAN_ACCESS,
    PYAS_PROCESS_TERMINATE_ACCESS,
    PYAS_USER_MESSAGE,
    RECT,
    SERVICE_STATUS_PROCESS,
    SHQUERYRBINFO,
    STORAGE_DESCRIPTOR_HEADER,
    STORAGE_DEVICE_DESCRIPTOR,
    STORAGE_DEVICE_PROPERTY,
    STORAGE_HOTPLUG_INFO,
    STORAGE_PROPERTY_QUERY,
    TOKEN_PRIVILEGES,
    UNICODE_STRING,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
    WINTRUST_DATA,
    WINTRUST_DATA_UNION,
    WINTRUST_FILE_INFO,
)
from PYAS_Autostart import AutostartMixin
from PYAS_Process import ProcessMixin
from PYAS_Maintenance import MaintenanceMixin
from PYAS_Threats import ThreatMixin


class ToolsMixin(AutostartMixin, ProcessMixin, MaintenanceMixin, ThreatMixin):
    def _find_windows_tool(self, *names):
        windows_dir = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
        search_dirs = [
            os.path.join(windows_dir, "Sysnative"),
            os.path.join(windows_dir, "System32"),
            windows_dir,
        ]

        for name in names:
            executable_name = name if name.lower().endswith(".exe") else name + ".exe"

            for directory in search_dirs:
                candidate = os.path.join(directory, executable_name)

                if os.path.isfile(candidate):
                    return candidate

            candidate = shutil.which(name)

            if candidate:
                return candidate

        return None

    def _run_windows_tool(self, tool_names, arguments, **kwargs):
        executable = self._find_windows_tool(*tool_names)

        if not executable:
            return None

        options = {"creationflags": 0x08000000}
        options.update(kwargs)

        try:
            return subprocess.run([executable, *arguments], **options)
        except (FileNotFoundError, OSError):
            log_exception("PYAS_Tools.ToolsMixin._run_windows_tool:43")
            return None

    def _run_powershell(self, command, **kwargs):
        return self._run_windows_tool(
            (r"WindowsPowerShell\v1.0\powershell.exe", "powershell.exe", "pwsh.exe"),
            [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-WindowStyle",
                "Hidden",
                "-Command",
                command,
            ],
            **kwargs,
        )

    def _clear_event_log(self, log_name):
        result = self._run_windows_tool(
            ("wevtutil.exe",),
            ["cl", log_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if result is not None and result.returncode == 0:
            return True

        try:
            wevtapi = ctypes.WinDLL("wevtapi", use_last_error=True)
            wevtapi.EvtClearLog.argtypes = [
                ctypes.wintypes.HANDLE,
                ctypes.wintypes.LPCWSTR,
                ctypes.wintypes.LPCWSTR,
                ctypes.wintypes.DWORD,
            ]
            wevtapi.EvtClearLog.restype = ctypes.wintypes.BOOL
            return bool(wevtapi.EvtClearLog(None, log_name, None, 0))

        except Exception:
            log_exception("PYAS_Tools.ToolsMixin._clear_event_log:69")
            return False

    def _manage_service_native(self, service_name, action):
        SC_MANAGER_CONNECT = 0x0001
        SERVICE_CHANGE_CONFIG = 0x0002
        DELETE = 0x00010000
        SERVICE_NO_CHANGE = 0xFFFFFFFF
        SERVICE_AUTO_START = 0x00000002
        SERVICE_DISABLED = 0x00000004

        try:
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            advapi32.OpenSCManagerW.argtypes = [
                ctypes.wintypes.LPCWSTR,
                ctypes.wintypes.LPCWSTR,
                ctypes.wintypes.DWORD,
            ]
            advapi32.OpenSCManagerW.restype = ctypes.wintypes.HANDLE
            advapi32.OpenServiceW.argtypes = [
                ctypes.wintypes.HANDLE,
                ctypes.wintypes.LPCWSTR,
                ctypes.wintypes.DWORD,
            ]
            advapi32.OpenServiceW.restype = ctypes.wintypes.HANDLE
            advapi32.CloseServiceHandle.argtypes = [ctypes.wintypes.HANDLE]
            advapi32.CloseServiceHandle.restype = ctypes.wintypes.BOOL

            manager = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)

            if not manager:
                return False

            service = None

            try:
                desired_access = DELETE if action == "delete" else SERVICE_CHANGE_CONFIG
                service = advapi32.OpenServiceW(manager, service_name, desired_access)

                if not service:
                    return False

                if action == "delete":
                    advapi32.DeleteService.argtypes = [ctypes.wintypes.HANDLE]
                    advapi32.DeleteService.restype = ctypes.wintypes.BOOL
                    return bool(advapi32.DeleteService(service))

                start_type = SERVICE_AUTO_START if action == "enable" else SERVICE_DISABLED
                advapi32.ChangeServiceConfigW.argtypes = [
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
                advapi32.ChangeServiceConfigW.restype = ctypes.wintypes.BOOL
                return bool(
                    advapi32.ChangeServiceConfigW(
                        service,
                        SERVICE_NO_CHANGE,
                        start_type,
                        SERVICE_NO_CHANGE,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                )
            finally:
                if service:
                    advapi32.CloseServiceHandle(service)

                advapi32.CloseServiceHandle(manager)
        except Exception:
            log_exception("PYAS_Tools.ToolsMixin._manage_service_native:137")
            return False

    def _manage_scheduled_task(self, task_path, action):
        schtasks_action = "/delete" if action == "delete" else "/change"
        arguments = [schtasks_action, "/tn", task_path]

        if action == "delete":
            arguments.append("/f")
        else:
            arguments.append("/enable" if action == "enable" else "/disable")

        result = self._run_windows_tool(
            ("schtasks.exe",), arguments, capture_output=True, text=True
        )

        if result is not None and result.returncode == 0:
            return True

        escaped_path = task_path.replace("'", "''")
        operation = {
            "delete": "Unregister-ScheduledTask -InputObject $Task -Confirm:$false",
            "enable": "Enable-ScheduledTask -InputObject $Task | Out-Null",
            "disable": "Disable-ScheduledTask -InputObject $Task | Out-Null",
        }.get(action)

        if not operation:
            return False

        command = (
            f"$FullName = '{escaped_path}'; "
            "$Task = Get-ScheduledTask -ErrorAction SilentlyContinue | "
            "Where-Object { ($_.TaskPath + $_.TaskName) -eq $FullName } | Select-Object -First 1; "
            f"if ($Task) {{ {operation} }} else {{ exit 1 }}"
        )
        result = self._run_powershell(command, capture_output=True, text=True)
        return bool(result and result.returncode == 0)

    def _reg_read(self, root, path, value_name):
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as reg:
                val, _ = winreg.QueryValueEx(reg, value_name)
                return val

        except Exception:
            log_exception("PYAS_Tools.ToolsMixin._reg_read:181")
            return None

    def _reg_write(self, root, path, value_name, value_type, value):
        try:
            with winreg.CreateKey(root, path) as reg:
                if value_name is None:
                    winreg.SetValue(reg, "", value_type, value)
                else:
                    winreg.SetValueEx(reg, value_name, 0, value_type, value)

                actual, actual_type = winreg.QueryValueEx(reg, value_name or "")
                return actual == value and actual_type == value_type
        except Exception:
            log_exception("ToolsMixin._reg_write")
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
            log_exception("PYAS_Tools.ToolsMixin._reg_delete:205")
            return False

    def start_daemon_thread(self, target, *args, **kwargs):
        t = threading.Thread(
            target=target,
            args=args,
            kwargs=kwargs,
            daemon=True,
            name=f"PYAS.{getattr(target, '__name__', 'worker')}",
        )
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
                log_exception("PYAS_Tools.ToolsMixin.norm_path:223")
                return None

        return path

    def path_equal(self, a, b):
        pa, pb = self.norm_path(a, must_exist=False), self.norm_path(b, must_exist=False)
        return os.path.normcase(pa) == os.path.normcase(pb) if pa and pb else False

    def get_file_version(self, file_path):
        pe = None

        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
            )

            for file_info in getattr(pe, "FileInfo", []):
                for info in file_info:
                    if getattr(info, "name", "") in ("StringFileInfo", b"StringFileInfo"):
                        for table in getattr(info, "StringTable", []):
                            for key, value in table.entries.items():
                                key = (
                                    key.decode("utf-8", "ignore")
                                    if isinstance(key, bytes)
                                    else str(key)
                                )

                                if key == "FileVersion":
                                    value = (
                                        value.decode("utf-8", "ignore")
                                        if isinstance(value, bytes)
                                        else str(value)
                                    )
                                    return value.strip()
        except Exception:
            log_exception("PYAS_Tools.ToolsMixin.get_file_version:246")
            pass
        finally:
            if pe is not None:
                pe.close()

        return "0.0.0.0"

    def compare_versions(self, v1, v2):
        try:
            val1 = tuple(int(x) for x in re.findall(r"\d+", re.sub(r"^[vV]\s*", "", str(v1))))
            val2 = tuple(int(x) for x in re.findall(r"\d+", re.sub(r"^[vV]\s*", "", str(v2))))
            return val1 >= val2

        except Exception:
            log_exception("PYAS_Tools.ToolsMixin.compare_versions:259")
            return False

    def check_update(self):
        try:
            current = self.pyas_config.get("version", "0.0.0")
            j = requests.get(
                "https://api.github.com/repos/87owo/PYAS/releases/latest",
                headers={"Accept": "application/vnd.github+json", "User-Agent": "PYAS"},
                timeout=10,
            ).json()
            latest = str(j.get("tag_name") or j.get("name") or "").strip()
            page = j.get("html_url") or "https://github.com/87owo/PYAS/releases"

            if latest:
                if not self.compare_versions(current, latest) and current != latest:
                    return {"has_update": True, "latest": latest, "current": current, "url": page}

                return {"has_update": False, "latest": latest, "current": current, "url": page}

        except Exception:
            log_exception("PYAS_Tools.ToolsMixin.check_update:274")
            pass

        return {"error": True}

    def calc_file_hash(self, file_path, block_size=65536):
        try:
            h = hashlib.sha256()

            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(block_size), b""):
                    h.update(chunk)

            return h.hexdigest()
        except Exception:
            log_exception("PYAS_Tools.ToolsMixin.calc_file_hash:285")
            return None
