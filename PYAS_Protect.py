from PYAS_Diagnostics import log_exception
import os
import time
import shutil
import msvcrt
import winreg
import threading
import subprocess
import copy
import ctypes
import ctypes.wintypes
from PYAS_Popup import build_popup_rule, normalized_path, popup_rule_matches
from PYAS_WinAPI import (
    FILE_NOTIFY_INFORMATION,
    LUID,
    MEMORY_BASIC_INFORMATION,
    POINT,
    PYAS_FULL_MESSAGE,
    PYAS_USER_MESSAGE,
    RECT,
    SERVICE_STATUS_PROCESS,
    TOKEN_PRIVILEGES,
)
from PYAS_WinAPI import (
    COPYDATASTRUCT,
    ERROR_LOCK_VIOLATION,
    ERROR_NOT_FOUND,
    ERROR_OPERATION_ABORTED,
    ERROR_SHARING_VIOLATION,
    FILE_ATTRIBUTE_NORMAL,
    FILE_LOCK_RETRY_SECONDS,
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
    LUID_AND_ATTRIBUTES,
    MIB_TCPROW_OWNER_PID,
    OPEN_EXISTING,
    OVERLAPPED,
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
    PYAS_MESSAGE,
    PYAS_PROCESS_NETWORK_ACCESS,
    PYAS_PROCESS_SCAN_ACCESS,
    PYAS_PROCESS_TERMINATE_ACCESS,
    SHQUERYRBINFO,
    STORAGE_DESCRIPTOR_HEADER,
    STORAGE_DEVICE_DESCRIPTOR,
    STORAGE_DEVICE_PROPERTY,
    STORAGE_HOTPLUG_INFO,
    STORAGE_PROPERTY_QUERY,
    UNICODE_STRING,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
    WINTRUST_DATA,
    WINTRUST_DATA_UNION,
    WINTRUST_FILE_INFO,
)
from PYAS_Driver import DriverMixin
from PYAS_System import SystemMixin
from PYAS_Realtime import RealtimeMixin
from PYAS_Popup import PopupWindowMixin


class ProtectMixin(DriverMixin, SystemMixin, RealtimeMixin, PopupWindowMixin):
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

    def _driver_whitelist_patterns(self, file_path, is_directory=None):
        normalized_path = self.norm_path(file_path, must_exist=False)

        if not normalized_path:
            return []

        if is_directory is None:
            is_directory = os.path.isdir(normalized_path)

        drive_letter = os.path.splitdrive(normalized_path)[0]
        driver_path = (
            "*" + normalized_path[len(drive_letter) :] if drive_letter else normalized_path
        )
        patterns = [driver_path]

        if is_directory:
            descendant_pattern = driver_path.rstrip("\\/") + "\\*"

            if descendant_pattern not in patterns:
                patterns.append(descendant_pattern)

        return patterns

    def sync_driver_whitelist(self, file_path, is_add=True, is_directory=None):
        with self.lock_driver:
            if not self.driver_port:
                return False

            patterns = self._driver_whitelist_patterns(file_path, is_directory)

            if not patterns:
                return False

            success = True

            for driver_path in patterns:
                msg = PYAS_USER_MESSAGE()
                msg.Command = 1 if is_add else 2
                bytes_returned = ctypes.wintypes.DWORD(0)

                try:
                    msg.Path = driver_path

                    if (
                        self.fltlib.FilterSendMessage(
                            self.driver_port,
                            ctypes.byref(msg),
                            ctypes.sizeof(msg),
                            None,
                            0,
                            ctypes.byref(bytes_returned),
                        )
                        != 0
                    ):
                        success = False
                except Exception:
                    log_exception("PYAS_Protect.ProtectMixin.sync_driver_whitelist:84")
                    success = False

            return success

    def _try_lock_file(self, file_path):
        fd = None

        try:
            fd = os.open(file_path, os.O_RDWR | os.O_BINARY)

            try:
                size = os.path.getsize(file_path)
            except Exception:
                log_exception("PYAS_Protect.ProtectMixin._try_lock_file:95")
                size = 1

            lock_size = size if size > 0 else 1
            msvcrt.locking(fd, msvcrt.LK_NBRLCK, lock_size)
            self.virus_lock[file_path] = (fd, lock_size)
            return True, None
        except Exception as e:
            log_exception("PYAS_Protect.ProtectMixin._try_lock_file:102")

            if fd is not None:
                try:
                    os.close(fd)
                except Exception:
                    log_exception("PYAS_Protect.ProtectMixin._try_lock_file:106")
                    pass

            return False, e

    def _queue_file_lock(self, file_path):
        self._schedule_file_task("lock", file_path, self._retry_file_lock, FILE_LOCK_RETRY_SECONDS)

    def _retry_file_lock(self, file_path):
        if not os.path.isfile(file_path):
            return

        with self.lock_file_ops:
            if file_path in self.virus_lock:
                return

            success, _ = self._try_lock_file(file_path)

        if not success:
            self._queue_file_lock(file_path)

    def lock_file(self, target_path, lock, quiet=False):
        if lock:
            if not os.path.exists(target_path):
                return False

            paths_to_lock = []

            if os.path.isdir(target_path):
                for root, _, files in os.walk(target_path):
                    for file_name in files:
                        paths_to_lock.append(os.path.join(root, file_name))
            else:
                paths_to_lock.append(target_path)

            failed_locks = []

            with self.lock_file_ops:
                for file_path in paths_to_lock:
                    if file_path in self.virus_lock:
                        continue

                    success, error = self._try_lock_file(file_path)

                    if not success:
                        failed_locks.append((file_path, error))

            for file_path, error in failed_locks:
                self._queue_file_lock(file_path)

                if not quiet:
                    self.write_log(
                        "INFO", "File Lock Deferred", source=file_path, detail=str(error)
                    )

            return not failed_locks

        self._cancel_pending_file_tasks("lock", target_path)

        with self.lock_file_ops:
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
                    log_exception("PYAS_Protect.ProtectMixin.lock_file:170")

                    if not quiet:
                        self.write_log(
                            "WARN", "unlock_file", source=file_path, detail=str(e), success=False
                        )
                finally:
                    try:
                        os.close(fd)
                    except Exception:
                        log_exception("PYAS_Protect.ProtectMixin.lock_file:176")
                        pass

                    del self.virus_lock[file_path]

        return True

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
                log_exception("PYAS_Protect.ProtectMixin.relock_file:201")
                pass

            time.sleep(5)
