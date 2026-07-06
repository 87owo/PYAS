import os, re, io, csv, time, shutil, threading
import pefile, hashlib, winreg, requests, subprocess
import ctypes, ctypes.wintypes

from concurrent.futures import ThreadPoolExecutor

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

class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", ctypes.wintypes.DWORD),
        ("HighPart", ctypes.wintypes.LONG)
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", ctypes.wintypes.DWORD)
    ]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", ctypes.wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1)
    ]

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
        ("dwServiceFlags", ctypes.wintypes.DWORD)
    ]

class POINT(ctypes.Structure):
    _fields_ = [
        ("x", ctypes.c_long),
        ("y", ctypes.c_long)
    ]

class RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long)
    ]

####################################################################################################

class ToolsMixin:
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

####################################################################################################

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

####################################################################################################

    def manage_named_list(self, list_key, files, action="add", lock_func=None):
        if list_key == "quarantine" and lock_func is None:
            lock_func = self.lock_file

        norm_paths = self.norm_path(files or [], must_exist=False)
        if isinstance(norm_paths, str):
            norm_paths = [norm_paths] if norm_paths else []

        if not norm_paths:
            return 0

        if list_key == "custom_rule":
            acted_items = []
            os.makedirs(self.path_rules, exist_ok=True)

            for file_path in norm_paths:
                if action == "add":
                    if os.path.exists(file_path) and file_path.lower().endswith(".json"):
                        dest = os.path.join(self.path_rules, os.path.basename(file_path))

                        if file_path != dest:
                            try:
                                shutil.copy2(file_path, dest)
                                acted_items.append(dest)

                            except Exception:
                                pass
                        else:
                            acted_items.append(dest)

                elif action == "remove":
                    try:
                        if os.path.exists(file_path):
                            os.remove(file_path)

                        acted_items.append(file_path)
                    except Exception:
                        pass

            if acted_items and getattr(self, 'driver_port', None):
                self.clear_driver_rules()
                for f in os.listdir(self.path_rules):
                    if f.lower().endswith(".json"):
                        self.load_driver_rule_file(os.path.join(self.path_rules, f))

            return len(acted_items)

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

####################################################################################################

    def remove_list_items(self, list_key, paths_to_remove):
        if list_key == "custom_rule":
            return self.manage_named_list(list_key, paths_to_remove, action="remove") > 0

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

####################################################################################################

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

####################################################################################################

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

####################################################################################################

    def calc_file_hash(self, file_path, block_size=65536):
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(block_size), b""): h.update(chunk)

            return h.hexdigest()
        except Exception:
            return None

####################################################################################################

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

####################################################################################################

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

####################################################################################################

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

####################################################################################################

    def kill_process(self, pid, expected_path=None):
        try:
            h = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if h:
                try:
                    file_path = self.norm_path(self.get_process_file(h))
                    if self.path_equal(file_path, self.file_pyas):
                        return False
                    if expected_path and not self.path_equal(file_path, expected_path):
                        return False

                    return bool(self.kernel32.TerminateProcess(h, 0))
                finally:
                    self.kernel32.CloseHandle(h)

        except Exception as e:
            self.write_log("WARN", "kill_process", pid=pid, detail=str(e), operate=True, success=False)
        return False

####################################################################################################

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

####################################################################################################

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

####################################################################################################

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

####################################################################################################

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
