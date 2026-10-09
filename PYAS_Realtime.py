from PYAS_WinAPI import iter_file_notifications
from PYAS_Scheduler import TaskScheduler
from PYAS_Diagnostics import log_exception
from PYAS_Diagnostics import observe_future
import os
import time
import threading
import ctypes
import ctypes.wintypes
from PYAS_WinAPI import FILE_NOTIFY_INFORMATION, MEMORY_BASIC_INFORMATION
from PYAS_WinAPI import (
    ERROR_LOCK_VIOLATION,
    ERROR_SHARING_VIOLATION,
    FILE_ATTRIBUTE_NORMAL,
    FILE_SCAN_DEBOUNCE_SECONDS,
    FILE_SCAN_RETRY_SECONDS,
    FILE_SHARE_READ,
    GENERIC_READ,
    INVALID_HANDLE_VALUE,
    OPEN_EXISTING,
    PYAS_PROCESS_NETWORK_ACCESS,
    PYAS_PROCESS_SCAN_ACCESS,
)


class RealtimeMixin:
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
                    h = self.kernel32.OpenProcess(PYAS_PROCESS_SCAN_ACCESS, False, pid)

                    if h:
                        with self.lock_config:
                            should_suspend = self.pyas_config.get("suspend_switch", True)

                        if should_suspend:
                            self.ntdll.NtSuspendProcess(h)

                            with self.lock_proc:
                                self.suspended_procs.add(h)

                        try:
                            observe_future(
                                self.proc_pool.submit(
                                    self.handle_new_process, pid, h, should_suspend
                                ),
                                "RealtimeMixin.handle_new_process",
                            )

                        except Exception:
                            log_exception("PYAS_Realtime.RealtimeMixin.protect_proc_thread:39")

                            if should_suspend:
                                self.ntdll.NtResumeProcess(h)

                                with self.lock_proc:
                                    self.suspended_procs.discard(h)

                            self.kernel32.CloseHandle(h)
            except Exception as e:
                log_exception("PYAS_Realtime.RealtimeMixin.protect_proc_thread:46")
                self.write_log("WARN", "protect_proc_thread", detail=str(e), success=False)

    def handle_new_process(self, pid, h=None, suspended=None):
        if suspended is None:
            with self.lock_config:
                suspended = self.pyas_config.get("suspend_switch", True)

        if not h:
            h = self.kernel32.OpenProcess(PYAS_PROCESS_SCAN_ACCESS, False, pid)

            if not h:
                return

            if suspended:
                self.ntdll.NtSuspendProcess(h)

                with self.lock_proc:
                    if not hasattr(self, "suspended_procs"):
                        self.suspended_procs = set()

                    self.suspended_procs.add(h)

        try:
            cmdline = self.get_process_cmdline(h)
            process_file = self.get_process_file(h)

            if "-scan" in cmdline and self.path_equal(process_file, self.file_pyas):
                return

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
                load_switch = self.pyas_config.get("load_switch", True)

            scan_targets = []

            for file_path in all_targets:
                if not file_path or not os.path.isfile(file_path):
                    continue

                if ext_filter and os.path.splitext(file_path)[-1].lower() not in suffix:
                    continue

                if self.is_in_whitelist(file_path):
                    continue

                if (
                    process_file
                    and process_file.lower().endswith("explorer.exe")
                    and "/select" in cmdline.lower()
                ):
                    continue

                scan_targets.append(file_path)

            if not scan_targets:
                return

            virus_found = False

            for file_path in scan_targets:
                result = self.safe_scan_engine(file_path)
                self.cloud_check(file_path)

                if result:
                    self._terminate_process_handle(h, pid=pid)
                    self.write_log(
                        "BLOCK",
                        "Process Block",
                        pid=pid,
                        source=file_path,
                        file_hash=self.calc_file_hash(file_path),
                    )
                    virus_found = True
                    break

            if not virus_found and load_switch:
                hidden_virus_path = self.scan_process_memory(pid, h)

                if hidden_virus_path:
                    self._terminate_process_handle(h, pid=pid)
                    self.write_log(
                        "BLOCK",
                        "Process DLL Block",
                        pid=pid,
                        source=hidden_virus_path,
                        file_hash=self.calc_file_hash(hidden_virus_path),
                    )

        finally:
            if suspended:
                try:
                    self.ntdll.NtResumeProcess(h)
                except Exception:
                    log_exception("PYAS_Realtime.RealtimeMixin.handle_new_process:123")
                    pass

                with self.lock_proc:
                    self.suspended_procs.discard(h)

            try:
                self.kernel32.CloseHandle(h)
            except Exception:
                log_exception("PYAS_Realtime.RealtimeMixin.handle_new_process:129")
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
            while address < max_address and self.kernel32.VirtualQueryEx(
                h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
            ):
                if mbi.State == 0x1000 and mbi.Type == 0x1000000:
                    if self.psapi.GetMappedFileNameW(
                        h_process, ctypes.c_void_p(address), buf, 1024
                    ):

                        raw_path = buf.value

                        if raw_path.startswith("\\"):
                            raw_path = self.device_path_to_drive(raw_path)

                        file_path = self.norm_path(raw_path)

                        if (
                            file_path
                            and file_path not in scanned_paths
                            and self.path_system not in file_path
                        ):

                            scanned_paths.add(file_path)
                            file_path_lower = file_path.lower()

                            if not file_path_lower.startswith(
                                system_dir
                            ) and not self.is_in_whitelist(file_path):
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
            if getattr(self, "h_dir_file", None):
                return

        hDir = self.kernel32.CreateFileW(
            self.path_user, 0x0001, 0x00000007, None, 3, 0x02000000, None
        )

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
                    res = self.kernel32.ReadDirectoryChangesW(
                        self.h_dir_file,
                        buffer,
                        ctypes.sizeof(buffer),
                        True,
                        0x0000001F,
                        ctypes.byref(bytes_returned),
                        None,
                        None,
                    )

                    if not res:
                        raise OSError(ctypes.get_last_error(), "Directory watcher read failed")

                    if bytes_returned.value == 0:
                        self._schedule_file_task(
                            "recovery", self.path_user, lambda _: self._recover_file_tasks(), 0
                        )
                        continue

                    for action, raw_filename in iter_file_notifications(
                        buffer, bytes_returned.value
                    ):
                        if raw_filename and action in [1, 3, 5]:
                            file_path = self.norm_path(
                                os.path.join(self.path_user, raw_filename), must_exist=True
                            )

                            if file_path and not self.is_in_whitelist(file_path):
                                norm_path = os.path.normcase(file_path)

                                if not (
                                    norm_path.startswith(temp_prefix)
                                    and norm_path[len(temp_prefix) :].startswith("_mei")
                                ):
                                    with self.lock_config:
                                        ext_filter = self.pyas_config.get("suffix_switch", True)
                                        suffix = self.pyas_config.get("suffix", [])

                                    if (
                                        not ext_filter
                                        or os.path.splitext(file_path)[-1].lower() in suffix
                                    ):
                                        self._queue_file_scan(file_path)

                except Exception:
                    log_exception("PYAS_Realtime.RealtimeMixin.protect_file_thread:230")

                    with self.lock_config:
                        enabled = self.pyas_config.get("document_switch", False)

                    if not enabled or self.closing:
                        break

                    self._schedule_file_task(
                        "recovery", self.path_user, lambda _: self._recover_file_tasks(), 0
                    )
                    time.sleep(0.25)
        finally:
            with self.lock_file_ops:
                if getattr(self, "h_dir_file", None):
                    try:
                        self.kernel32.CloseHandle(self.h_dir_file)
                    except Exception:
                        log_exception("PYAS_Realtime.RealtimeMixin.protect_file_thread:237")
                        pass

                    self.h_dir_file = None

    def _cancel_pending_file_tasks(self, task_name=None, target_path=None):
        scheduler = getattr(self, "file_scheduler", None)

        if scheduler is None:
            return

        target = os.path.normcase(target_path) if target_path else None
        prefix = target + os.sep if target else None
        scheduler.cancel(
            lambda key: (not task_name or key[0] == task_name)
            and (not target or key[1] == target or key[1].startswith(prefix))
        )

    def _cancel_pending_file_scans(self):
        self._cancel_pending_file_tasks("scan")

    def _schedule_file_task(self, task_name, file_path, callback, delay):
        with self.lock_file_ops:
            if self.closing:
                return False

            if getattr(self, "file_scheduler", None) is None:
                self.file_scheduler = TaskScheduler(self._recover_file_tasks)

            scheduler = self.file_scheduler

        return scheduler.schedule(
            (task_name, os.path.normcase(file_path)),
            delay,
            callback,
            (file_path,),
            critical=task_name in ("delete", "lock", "verify"),
        )

    def _recover_file_tasks(self):
        self.write_log(
            "WARN",
            "File Event Recovery",
            detail="Pending task capacity reached; recovering by rescan",
            success=False,
        )

        with self.lock_config:
            quarantined = list(self.pyas_config.get("quarantine", []))

        for entry in quarantined:
            if self.closing:
                return

            path = entry.get("file") if isinstance(entry, dict) else entry

            if path:
                self.lock_file(path, True, quiet=True)

        for file_path, _ in self.yield_files(self.path_user):
            with self.lock_config:
                enabled = self.pyas_config.get("document_switch", False)
                ext_filter = self.pyas_config.get("suffix_switch", True)
                suffix = self.pyas_config.get("suffix", [])

            if self.closing or not enabled:
                break

            if self.is_in_whitelist(file_path):
                continue

            norm_path = os.path.normcase(file_path)
            temp_prefix = os.path.normcase(self.path_temp).rstrip(os.sep) + os.sep

            if norm_path.startswith(temp_prefix) and norm_path[len(temp_prefix) :].startswith(
                "_mei"
            ):
                continue

            if not ext_filter or os.path.splitext(norm_path)[-1] in suffix:
                self.handle_new_file(file_path)

    def _queue_file_scan(self, file_path, delay=FILE_SCAN_DEBOUNCE_SECONDS):
        self._schedule_file_task("scan", file_path, self.handle_new_file, delay)

    def _acquire_file_scan_gate(self, file_path):
        ctypes.set_last_error(0)
        handle = self.kernel32.CreateFileW(
            file_path,
            GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )

        if not handle or handle == INVALID_HANDLE_VALUE:
            return None, ctypes.get_last_error()

        return handle, 0

    def handle_new_file(self, file_path):
        try:
            with self.lock_config:
                if not self.pyas_config.get("document_switch", False):
                    return

            gate_handle, error = self._acquire_file_scan_gate(file_path)

            if not gate_handle:
                if error in (ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION):
                    self._queue_file_scan(file_path, FILE_SCAN_RETRY_SECONDS)

                return

            try:
                with self.lock_file_ops:
                    if file_path in self.virus_lock:
                        return

                result = self.safe_scan_engine(file_path)
                self.cloud_check(file_path)

                if result:
                    if (
                        self.manage_named_list(
                            "quarantine", [file_path], action="add", lock_func=self.lock_file
                        )
                        > 0
                    ):
                        self.write_log(
                            "BLOCK",
                            "File Block",
                            source=file_path,
                            file_hash=self.calc_file_hash(file_path),
                        )
            finally:
                self.kernel32.CloseHandle(gate_handle)
        except Exception:
            log_exception("PYAS_Realtime.RealtimeMixin.handle_new_file:341")
            pass

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
                    observe_future(
                        self.protect_pool.submit(self.handle_new_connection, key),
                        "RealtimeMixin.handle_new_connection",
                    )

            except Exception as e:
                log_exception("PYAS_Realtime.RealtimeMixin.protect_net_thread:363")
                self.write_log("WARN", "protect_net_thread", detail=str(e), success=False)

        with self.lock_net:
            self.exist_connections = set()

    def handle_new_connection(self, key):
        pid, remote_addr, remote_port = key

        try:
            h = self.kernel32.OpenProcess(PYAS_PROCESS_NETWORK_ACCESS, False, pid)

            if not h:
                return

            try:
                remote_ip = f"{remote_addr & 0xFF}.{(remote_addr >> 8) & 0xFF}.{(remote_addr >> 16) & 0xFF}.{(remote_addr >> 24) & 0xFF}"
                file_path = self.norm_path(self.get_process_file(h))

                if (
                    file_path
                    and not self.is_in_whitelist(file_path)
                    and hasattr(self.heuristic, "network")
                    and remote_ip in self.heuristic.network
                ):
                    self._terminate_process_handle(h, pid=pid)
                    self.write_log(
                        "BLOCK",
                        "Network Block",
                        pid=pid,
                        source=file_path,
                        target=remote_ip,
                        file_hash=self.calc_file_hash(file_path),
                    )

            finally:
                self.kernel32.CloseHandle(h)

        except Exception as e:
            log_exception("PYAS_Realtime.RealtimeMixin.handle_new_connection:387")
            self.write_log("WARN", "handle_new_connection", pid=pid, detail=str(e), success=False)
