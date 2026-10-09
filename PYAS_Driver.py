from PYAS_Diagnostics import log_exception
import os
import time
import winreg
import threading
import ctypes
import ctypes.wintypes
from PYAS_WinAPI import (
    LUID,
    PYAS_FULL_MESSAGE,
    PYAS_USER_MESSAGE,
    SERVICE_STATUS_PROCESS,
    TOKEN_PRIVILEGES,
)
from PYAS_WinAPI import (
    ERROR_NOT_FOUND,
    ERROR_OPERATION_ABORTED,
    FLT_PORT_FLAG_SYNC_HANDLE,
    HRESULT_IO_PENDING,
    OVERLAPPED,
    PYAS_CONNECTION_CONTEXT,
    PYAS_CONNECTION_MAGIC,
    PYAS_CONNECTION_VERSION,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
)


class DriverMixin:
    def _query_service_state_handle(self, service):
        status = SERVICE_STATUS_PROCESS()
        needed = ctypes.wintypes.DWORD(0)
        buffer = ctypes.cast(ctypes.byref(status), ctypes.POINTER(ctypes.c_ubyte))

        if not self.advapi32.QueryServiceStatusEx(
            service, 0, buffer, ctypes.sizeof(status), ctypes.byref(needed)
        ):
            return None, ctypes.get_last_error()

        return int(status.dwCurrentState), 0

    def _query_driver_service_state(self):
        scm = self.advapi32.OpenSCManagerW(None, None, 0x0001)

        if not scm:
            return None

        service = None

        try:
            service = self.advapi32.OpenServiceW(scm, "PYAS_Driver", 0x0004)

            if not service:
                return None

            state, _ = self._query_service_state_handle(service)
            return state
        finally:
            if service:
                self.advapi32.CloseServiceHandle(service)

            self.advapi32.CloseServiceHandle(scm)

    def _get_driver_client_image_path(self):
        buffer = ctypes.create_unicode_buffer(32768)
        size = ctypes.wintypes.DWORD(len(buffer))

        if not self.kernel32.QueryFullProcessImageNameW(
            self.kernel32.GetCurrentProcess(), 0, buffer, ctypes.byref(size)
        ):
            return None

        image_path = os.path.abspath(buffer.value)
        drive, tail = os.path.splitdrive(image_path)

        if not drive or not tail:
            return None

        device_buffer = ctypes.create_unicode_buffer(32768)

        if not self.kernel32.QueryDosDeviceW(drive, device_buffer, len(device_buffer)):
            return None

        return device_buffer.value.rstrip("\\") + tail

    def _configure_driver_identity(self):
        image_path = self._get_driver_client_image_path()

        if not image_path:
            return False, ctypes.get_last_error() or 1

        try:
            access = winreg.KEY_SET_VALUE | getattr(winreg, "KEY_WOW64_64KEY", 0)

            with winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\PYAS_Driver",
                0,
                access,
            ) as key:
                winreg.SetValueEx(key, "ClientImagePath", 0, winreg.REG_SZ, image_path)

            return True, 0
        except OSError as e:
            log_exception("PYAS_Driver.DriverMixin._configure_driver_identity:74")
            return False, int(getattr(e, "winerror", 0) or 1)

    def _ensure_driver_service(self):
        desired_service_access = 0x0002 | 0x0004 | 0x0010 | 0x00010000
        dependencies = ctypes.create_unicode_buffer("FltMgr\0\0")
        dependencies_ptr = ctypes.cast(dependencies, ctypes.wintypes.LPCWSTR)
        last_error = 0

        for attempt in range(20):
            scm = self.advapi32.OpenSCManagerW(None, None, 0x0001 | 0x0002)

            if not scm:
                return False, ctypes.get_last_error()

            service = None

            try:
                ctypes.set_last_error(0)
                service = self.advapi32.CreateServiceW(
                    scm,
                    "PYAS_Driver",
                    "PYAS_Driver",
                    desired_service_access,
                    0x00000001,
                    0x00000003,
                    0x00000001,
                    self.path_drivers,
                    "FSFilter Activity Monitor",
                    None,
                    dependencies_ptr,
                    None,
                    None,
                )

                if not service:
                    last_error = ctypes.get_last_error()

                    if last_error in (1073, 1078):
                        service = self.advapi32.OpenServiceW(
                            scm, "PYAS_Driver", desired_service_access
                        )

                        if not service:
                            last_error = ctypes.get_last_error()

                    elif last_error == 1072:
                        pass

                if service:
                    ctypes.set_last_error(0)
                    changed = self.advapi32.ChangeServiceConfigW(
                        service,
                        0x00000001,
                        0x00000003,
                        0x00000001,
                        self.path_drivers,
                        "FSFilter Activity Monitor",
                        None,
                        dependencies_ptr,
                        None,
                        None,
                        None,
                    )

                    if not changed:
                        last_error = ctypes.get_last_error()
                        return False, last_error

                    return True, 0
            finally:
                if service:
                    self.advapi32.CloseServiceHandle(service)

                self.advapi32.CloseServiceHandle(scm)

            if last_error != 1072:
                break

            if attempt < 19:
                time.sleep(0.05)

        return False, last_error or 1

    def _start_driver_service(self):
        scm = self.advapi32.OpenSCManagerW(None, None, 0x0001)

        if not scm:
            return False, ctypes.get_last_error()

        service = None

        try:
            service = self.advapi32.OpenServiceW(scm, "PYAS_Driver", 0x0004 | 0x0010)

            if not service:
                return False, ctypes.get_last_error()

            state, error = self._query_service_state_handle(service)

            if state in (2, 4):
                return True, 0

            if error:
                return False, error

            ctypes.set_last_error(0)

            if self.advapi32.StartServiceW(service, 0, None):
                return True, 0

            error = ctypes.get_last_error()

            if error == 1056:
                return True, 0

            return False, error
        finally:
            if service:
                self.advapi32.CloseServiceHandle(service)

            self.advapi32.CloseServiceHandle(scm)

    def uninstall_system_driver(self):
        if not self.stop_system_driver():
            return False, 1051

        return self._delete_driver_service()

    def _delete_driver_service(self, timeout=15.0):
        deadline = time.monotonic() + timeout
        last_error = 0
        delete_requested = False

        while time.monotonic() < deadline:
            scm = self.advapi32.OpenSCManagerW(None, None, 0x0001)

            if not scm:
                return False, ctypes.get_last_error()

            service = None

            try:
                ctypes.set_last_error(0)
                service = self.advapi32.OpenServiceW(scm, "PYAS_Driver", 0x0004 | 0x00010000)

                if not service:
                    last_error = ctypes.get_last_error()

                    if last_error == 1060:
                        return True, 0

                    if last_error != 1072:
                        return False, last_error
                else:
                    state, status_error = self._query_service_state_handle(service)

                    if status_error:
                        return False, status_error

                    if state not in (2, 3, 4) and not delete_requested:
                        ctypes.set_last_error(0)

                        if self.advapi32.DeleteService(service):
                            delete_requested = True
                            last_error = 1072
                        else:
                            last_error = ctypes.get_last_error()

                            if last_error == 1060:
                                return True, 0

                            if last_error == 1072:
                                delete_requested = True
                            else:
                                return False, last_error
                    elif state in (2, 3, 4):
                        last_error = 1051
            finally:
                if service:
                    self.advapi32.CloseServiceHandle(service)

                self.advapi32.CloseServiceHandle(scm)

            time.sleep(0.1)

        return False, last_error or 1072

    def install_system_driver(self):
        try:
            ensured, service_error = self._ensure_driver_service()

            if not ensured:
                self.write_log(
                    "WARN",
                    "Driver Service",
                    detail=f"CreateServiceW/ChangeServiceConfigW failed: 0x{service_error & 0xFFFFFFFF:08X}",
                    success=False,
                )
                return False

            configured, identity_error = self._configure_driver_identity()

            if not configured:
                self.write_log(
                    "WARN",
                    "Driver Identity",
                    detail=f"ClientImagePath configuration failed: 0x{identity_error & 0xFFFFFFFF:08X}",
                    success=False,
                )
                return False

            self._reg_write(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\PYAS_Driver\Instances",
                "DefaultInstance",
                winreg.REG_SZ,
                "PYAS Instance",
            )
            self._reg_write(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\PYAS_Driver\Instances\PYAS Instance",
                "Altitude",
                winreg.REG_SZ,
                "320000",
            )
            self._reg_write(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\PYAS_Driver\Instances\PYAS Instance",
                "Flags",
                winreg.REG_DWORD,
                0,
            )

            started, start_error = self._start_driver_service()

            if not started:
                self.write_log(
                    "WARN",
                    "Driver Service",
                    detail=f"StartServiceW failed: 0x{start_error & 0xFFFFFFFF:08X}",
                    success=False,
                )
                return False

            final_state = None
            last_start_attempt = time.monotonic()
            deadline = time.monotonic() + 3.0

            while time.monotonic() < deadline:
                service_state = self._query_driver_service_state()

                if service_state == 4:
                    final_state = self._query_driver_state()

                    if final_state == 2:
                        return True

                    if final_state in (4, 5):
                        break
                elif service_state == 1:
                    now = time.monotonic()

                    if now - last_start_attempt >= 0.1:
                        started, start_error = self._start_driver_service()
                        last_start_attempt = now

                        if not started:
                            break
                elif service_state is None:
                    break

                time.sleep(0.02)

            if self.check_system_driver():
                self.stop_system_driver()

            detail = (
                "Driver entered unload-retry state during startup"
                if final_state == 4
                else "Driver did not reach running state"
            )
            self.write_log("WARN", "Driver Protection", detail=detail, success=False)
            return False

        except Exception as e:
            log_exception("PYAS_Driver.DriverMixin.install_system_driver:267")
            self.write_log("WARN", "install_system_driver", detail=str(e), success=False)
            return False

    def _driver_handle_value(self, handle):
        if handle is None:
            return None

        value = getattr(handle, "value", handle)

        if value is None:
            return None

        try:
            return int(value)
        except Exception:
            log_exception("PYAS_Driver.DriverMixin._driver_handle_value:281")
            return None

    def _connect_driver_port(self, asynchronous=False):
        context = PYAS_CONNECTION_CONTEXT()
        context.Size = ctypes.sizeof(context)
        context.Version = PYAS_CONNECTION_VERSION
        context.Magic = PYAS_CONNECTION_MAGIC
        context.ProcessId = os.getpid()

        temp_port = ctypes.wintypes.HANDLE()
        status = self.fltlib.FilterConnectCommunicationPort(
            "\\PYAS_Output_Pipe",
            0 if asynchronous else FLT_PORT_FLAG_SYNC_HANDLE,
            ctypes.byref(context),
            ctypes.sizeof(context),
            None,
            ctypes.byref(temp_port),
        )

        if status != 0:
            return None

        return temp_port

    def _detach_driver_port(self, expected_port=None):
        expected_value = self._driver_handle_value(expected_port)

        with self.lock_driver:
            current_port = self.driver_port
            current_value = self._driver_handle_value(current_port)

            if current_value is None:
                return None

            if expected_port is not None and current_value != expected_value:
                return None

            self.driver_port = None
            return current_port

    def _close_driver_port(self, expected_port=None):
        port = self._detach_driver_port(expected_port)

        if not port:
            return False

        try:
            self.kernel32.CloseHandle(port)
        except Exception:
            log_exception("PYAS_Driver.DriverMixin._close_driver_port:326")
            pass

        return True

    def _driver_listener_should_run(self):
        if self.driver_stop_event.is_set():
            return False

        with self.lock_config:
            return bool(self.pyas_config.get("driver_switch", False))

    def start_driver_listener(self, wait_ready=True):
        with self.lock_driver:
            current = self.driver_listener_thread

            if current and current.is_alive():
                return (
                    self.driver_listener_ready_event.is_set()
                    and not self.driver_stop_event.is_set()
                )

            self.driver_stop_event.clear()
            self.driver_listener_ready_event.clear()
            self.driver_listener_failed_event.clear()
            thread = threading.Thread(target=self.pipe_server_thread, daemon=True)
            self.driver_listener_thread = thread
            thread.start()

        if not wait_ready:
            return True

        deadline = time.monotonic() + 5.0

        while time.monotonic() < deadline:
            if self.driver_listener_ready_event.wait(0.02):
                return True

            if self.driver_listener_failed_event.is_set() or not thread.is_alive():
                break

        self._stop_driver_listener()
        return False

    def _stop_driver_listener(self):
        self.driver_stop_event.set()

        with self.lock_driver:
            thread = self.driver_listener_thread
            port = self.driver_port

        if port:
            try:
                self.kernel32.CancelIoEx(port, None)
            except Exception:
                log_exception("PYAS_Driver.DriverMixin._stop_driver_listener:373")
                pass

        if thread and thread is not threading.current_thread():
            thread.join(timeout=2.0)

        alive = bool(thread and thread.is_alive())

        if not alive:
            with self.lock_driver:
                if self.driver_listener_thread is thread:
                    self.driver_listener_thread = None

            self.driver_listener_ready_event.clear()
            self._close_driver_port()

        return not alive

    def _resume_driver_listener(self):
        if not self.check_system_driver():
            return False

        with self.lock_config:
            enabled = bool(self.pyas_config.get("driver_switch", False))

        if not enabled:
            return False

        self._close_driver_port()
        return self.start_driver_listener(wait_ready=True)

    def _set_driver_unload_authorization(self, enabled):
        msg = PYAS_USER_MESSAGE()
        msg.Command = 5 if enabled else 6
        msg.Path = ""

        for _ in range(3):
            if not self._ensure_driver_port():
                time.sleep(0.1)
                continue

            with self.lock_driver:
                current_port = self.driver_port

                if not current_port:
                    continue

                bytes_returned = ctypes.wintypes.DWORD(0)

                try:
                    status = self.fltlib.FilterSendMessage(
                        current_port,
                        ctypes.byref(msg),
                        ctypes.sizeof(msg),
                        None,
                        0,
                        ctypes.byref(bytes_returned),
                    )
                except Exception as e:
                    log_exception("PYAS_Driver.DriverMixin._set_driver_unload_authorization:427")
                    self.write_log(
                        "WARN", "Driver Unload Authorization", detail=str(e), success=False
                    )
                    status = -1

            if status == 0:
                return True

            self._close_driver_port(current_port)
            time.sleep(0.1)

        return False

    def _ensure_driver_port(self):
        for _ in range(20):
            with self.lock_driver:
                if self.driver_port:
                    return True

            temp_port = self._connect_driver_port()

            if temp_port:
                with self.lock_driver:
                    if not self.driver_port:
                        self.driver_port = temp_port
                        return True

                try:
                    self.kernel32.CloseHandle(temp_port)
                except Exception:
                    log_exception("PYAS_Driver.DriverMixin._ensure_driver_port:454")
                    pass

                return True

            time.sleep(0.05)

        return False

    def _query_driver_state(self):
        for use_existing in (True, False):
            local_port = None
            port = None

            if use_existing:
                with self.lock_driver:
                    if self.driver_port:
                        port = self.driver_port

                if not port:
                    continue
            else:
                local_port = self._connect_driver_port()

                if not local_port:
                    return None

                port = local_port

            msg = PYAS_USER_MESSAGE()
            msg.Command = 7
            msg.Path = ""
            state = ctypes.wintypes.DWORD(0)
            bytes_returned = ctypes.wintypes.DWORD(0)

            try:
                status = self.fltlib.FilterSendMessage(
                    port,
                    ctypes.byref(msg),
                    ctypes.sizeof(msg),
                    ctypes.byref(state),
                    ctypes.sizeof(state),
                    ctypes.byref(bytes_returned),
                )

                if status == 0 and bytes_returned.value == ctypes.sizeof(state):
                    return int(state.value)
            except Exception:
                log_exception("PYAS_Driver.DriverMixin._query_driver_state:496")
                pass
            finally:
                if local_port:
                    try:
                        self.kernel32.CloseHandle(local_port)
                    except Exception:
                        log_exception("PYAS_Driver.DriverMixin._query_driver_state:502")
                        pass

            if use_existing:
                self._close_driver_port(port)

        return None

    def _enable_token_privilege(self, privilege_name):
        token = ctypes.wintypes.HANDLE()
        desired_access = 0x0020 | 0x0008

        if not self.advapi32.OpenProcessToken(
            self.kernel32.GetCurrentProcess(), desired_access, ctypes.byref(token)
        ):
            return None, ctypes.get_last_error()

        luid = LUID()

        if not self.advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid)):
            error = ctypes.get_last_error()
            self.kernel32.CloseHandle(token)
            return None, error

        new_state = TOKEN_PRIVILEGES()
        new_state.PrivilegeCount = 1
        new_state.Privileges[0].Luid = luid
        new_state.Privileges[0].Attributes = 0x00000002

        previous_state = TOKEN_PRIVILEGES()
        return_length = ctypes.wintypes.DWORD(0)
        ctypes.set_last_error(0)

        adjusted = self.advapi32.AdjustTokenPrivileges(
            token,
            False,
            ctypes.byref(new_state),
            ctypes.sizeof(previous_state),
            ctypes.byref(previous_state),
            ctypes.byref(return_length),
        )
        error = ctypes.get_last_error()

        if not adjusted or error == 1300:
            self.kernel32.CloseHandle(token)
            return None, error or 1

        return (token, previous_state, return_length.value), 0

    def _restore_token_privilege(self, privilege_state):
        if not privilege_state:
            return

        token, previous_state, previous_length = privilege_state

        try:
            if previous_length:
                self.advapi32.AdjustTokenPrivileges(
                    token, False, ctypes.byref(previous_state), 0, None, None
                )
        finally:
            self.kernel32.CloseHandle(token)

    def _filter_unload_with_privilege(self, filter_name):
        result = {
            "status": None,
            "privilege_error": 0,
            "authorization_failed": False,
            "exception": None,
            "attempts": 0,
        }
        privilege_state = None
        unload_authorized = False

        self.driver_unload_worker = None
        self.driver_unload_result = result

        try:
            privilege_state, privilege_error = self._enable_token_privilege("SeLoadDriverPrivilege")

            if not privilege_state:
                result["privilege_error"] = privilege_error
                return result

            retryable_statuses = {0x80070522, 0x80070005, 0x800700AA}

            for delay in (0.0, 0.05, 0.15):
                if delay:
                    time.sleep(delay)

                if not self.check_system_driver():
                    result["status"] = 0
                    unload_authorized = False
                    return result

                if not self._set_driver_unload_authorization(True):
                    continue

                unload_authorized = True
                result["attempts"] += 1
                unload_status = self.fltlib.FilterUnload(filter_name)
                result["status"] = unload_status

                if unload_status == 0:
                    unload_authorized = False
                    return result

                revoked = False

                if self.check_system_driver():
                    try:
                        revoked = self._set_driver_unload_authorization(False)
                    except Exception:
                        log_exception("PYAS_Driver.DriverMixin._filter_unload_with_privilege:606")
                        revoked = False

                unload_authorized = not revoked

                if (unload_status & 0xFFFFFFFF) not in retryable_statuses:
                    return result

            if result["status"] is None:
                result["authorization_failed"] = True

        except Exception as e:
            log_exception("PYAS_Driver.DriverMixin._filter_unload_with_privilege:616")
            result["exception"] = str(e)
        finally:
            if unload_authorized and self.check_system_driver():
                try:
                    self._set_driver_unload_authorization(False)
                except Exception:
                    log_exception("PYAS_Driver.DriverMixin._filter_unload_with_privilege:622")
                    pass

            self._restore_token_privilege(privilege_state)

        return result

    def stop_system_driver(self):
        with self.lock_driver_unload:
            runtime_unloaded = False
            unload_confirmed = False

            try:
                if not self._stop_driver_listener():
                    self.write_log(
                        "WARN",
                        "Driver Protection",
                        detail="Driver listener cancellation did not complete",
                        success=False,
                    )
                    return False

                if not self.check_system_driver():
                    runtime_unloaded = True
                    unload_confirmed = True
                else:
                    if not self._ensure_driver_port():
                        if not self.check_system_driver():
                            runtime_unloaded = True
                            unload_confirmed = True
                        else:
                            self.write_log(
                                "WARN",
                                "Driver Protection",
                                detail="Control port unavailable",
                                success=False,
                            )
                            return False

                    if not runtime_unloaded:
                        unload_result = self._filter_unload_with_privilege("PYAS_Driver")

                        if unload_result["privilege_error"]:
                            error = unload_result["privilege_error"]
                            self.write_log(
                                "WARN",
                                "Driver Protection",
                                detail=f"SeLoadDriverPrivilege unavailable: 0x{error & 0xFFFFFFFF:08X}",
                                success=False,
                            )
                            return False

                        if unload_result["authorization_failed"]:
                            self.write_log(
                                "WARN",
                                "Driver Protection",
                                detail="Unload authorization rejected",
                                success=False,
                            )
                            return False

                        if unload_result["exception"]:
                            self.write_log(
                                "WARN",
                                "stop_system_driver",
                                detail=unload_result["exception"],
                                success=False,
                            )
                            return False

                        unload_status = unload_result["status"]

                        if unload_status == 0:
                            runtime_unloaded = True
                            unload_confirmed = True
                        elif not self.check_system_driver():
                            runtime_unloaded = True
                            unload_confirmed = True
                        else:
                            attempts = unload_result["attempts"]
                            self.write_log(
                                "WARN",
                                "Driver Protection",
                                detail=f"FilterUnload failed after {attempts} attempt(s): 0x{unload_status & 0xFFFFFFFF:08X}",
                                success=False,
                            )
                            return False

                self._close_driver_port()

                if unload_confirmed:
                    deadline = time.monotonic() + 0.5

                    while time.monotonic() < deadline and self.check_system_driver():
                        time.sleep(0.01)

                    if self.check_system_driver():
                        self.write_log(
                            "INFO",
                            "Driver Protection",
                            detail="Filter unloaded; SCM state is still settling",
                        )

                return runtime_unloaded
            except Exception as e:
                log_exception("PYAS_Driver.DriverMixin.stop_system_driver:689")
                self.write_log("WARN", "stop_system_driver", detail=str(e), success=False)
                return False
            finally:
                if not runtime_unloaded and self.check_system_driver():
                    self._resume_driver_listener()

    def check_system_driver(self):
        runtime_state = self._query_driver_state()

        if runtime_state in (1, 2, 3, 4):
            return True

        service_state = self._query_driver_service_state()
        return service_state in (2, 3, 4)

    def clear_driver_rules(self):
        with self.lock_driver:
            if not self.driver_port:
                return False

            msg = PYAS_USER_MESSAGE()
            msg.Command = 4
            msg.Path = ""
            bytes_returned = ctypes.wintypes.DWORD(0)

            try:
                return (
                    self.fltlib.FilterSendMessage(
                        self.driver_port,
                        ctypes.byref(msg),
                        ctypes.sizeof(msg),
                        None,
                        0,
                        ctypes.byref(bytes_returned),
                    )
                    == 0
                )
            except Exception:
                log_exception("PYAS_Driver.DriverMixin.clear_driver_rules:723")
                return False

    def load_driver_rule_file(self, json_path):
        with self.lock_driver:
            if not self.driver_port:
                return False

            norm_path = os.path.abspath(json_path)

            if not os.path.exists(norm_path):
                return False

            nt_path = f"\\??\\{norm_path}"

            msg = PYAS_USER_MESSAGE()
            msg.Command = 3
            msg.Path = nt_path
            bytes_returned = ctypes.wintypes.DWORD(0)

            try:
                return (
                    self.fltlib.FilterSendMessage(
                        self.driver_port,
                        ctypes.byref(msg),
                        ctypes.sizeof(msg),
                        None,
                        0,
                        ctypes.byref(bytes_returned),
                    )
                    == 0
                )
            except Exception:
                log_exception("PYAS_Driver.DriverMixin.load_driver_rule_file:751")
                return False

    def _cancel_driver_receive(self, port, overlapped):
        try:
            ctypes.set_last_error(0)
            cancelled = self.kernel32.CancelIoEx(port, ctypes.byref(overlapped))
            error = ctypes.get_last_error()

            if not cancelled and error not in (0, ERROR_NOT_FOUND):
                return False

            wait_status = self.kernel32.WaitForSingleObject(overlapped.hEvent, 1000)

            if wait_status != WAIT_OBJECT_0:
                return False

            transferred = ctypes.wintypes.DWORD(0)
            self.kernel32.GetOverlappedResult(
                port, ctypes.byref(overlapped), ctypes.byref(transferred), False
            )
            return True
        except Exception:
            log_exception("PYAS_Driver.DriverMixin._cancel_driver_receive:774")
            return False

    def _receive_driver_message(self, port):
        message = PYAS_FULL_MESSAGE()
        overlapped = OVERLAPPED()
        event_handle = self.kernel32.CreateEventW(None, True, False, None)

        if not event_handle:
            return "error", None

        overlapped.hEvent = event_handle

        try:
            status = self.fltlib.FilterGetMessage(
                port,
                ctypes.byref(message),
                ctypes.sizeof(PYAS_FULL_MESSAGE),
                ctypes.byref(overlapped),
            )

            if status == 0:
                return "message", message

            if (status & 0xFFFFFFFF) != HRESULT_IO_PENDING:
                return "disconnect", None

            while True:
                if self.driver_stop_event.is_set():
                    self._cancel_driver_receive(port, overlapped)
                    return "stop", None

                wait_status = self.kernel32.WaitForSingleObject(event_handle, 20)

                if wait_status == WAIT_TIMEOUT:
                    continue

                if wait_status != WAIT_OBJECT_0:
                    self._cancel_driver_receive(port, overlapped)
                    return "error", None

                transferred = ctypes.wintypes.DWORD(0)

                if self.kernel32.GetOverlappedResult(
                    port, ctypes.byref(overlapped), ctypes.byref(transferred), False
                ):
                    return "message", message

                error = ctypes.get_last_error()

                if error == ERROR_OPERATION_ABORTED and self.driver_stop_event.is_set():
                    return "stop", None

                return "disconnect", None
        finally:
            self.kernel32.CloseHandle(event_handle)

    def pipe_server_thread(self):
        owned_port = None
        ready = False

        try:
            while self._driver_listener_should_run():
                temp_port = self._connect_driver_port(asynchronous=True)

                if not temp_port:
                    self.driver_stop_event.wait(0.02)
                    continue

                if not self._driver_listener_should_run():
                    self.kernel32.CloseHandle(temp_port)
                    break

                with self.lock_driver:
                    if self.driver_port:
                        accepted = False
                    else:
                        self.driver_port = temp_port
                        owned_port = temp_port
                        accepted = True

                if not accepted:
                    self.kernel32.CloseHandle(temp_port)
                    self.driver_stop_event.wait(0.02)
                    continue

                rule_files = []

                if os.path.exists(self.path_rules):
                    rule_files = sorted(
                        os.path.join(self.path_rules, name)
                        for name in os.listdir(self.path_rules)
                        if name.lower().endswith(".json") and name.lower() != "rules_driver_p1.json"
                    )

                load_failed = False

                for rule_file in rule_files:
                    if self.driver_stop_event.is_set() or not self.load_driver_rule_file(rule_file):
                        load_failed = True
                        break

                if load_failed:
                    self.driver_listener_failed_event.set()
                    break

                with self.lock_config:
                    whitelist = list(self.pyas_config.get("white_list", []))

                for item in whitelist:
                    if self.driver_stop_event.is_set():
                        break

                    if isinstance(item, dict) and item.get("file"):
                        self.sync_driver_whitelist(item["file"], True, item.get("is_dir"))

                if self.driver_stop_event.is_set():
                    break

                ready = True
                self.driver_listener_ready_event.set()

                while self._driver_listener_should_run():
                    with self.lock_driver:
                        current_port = self.driver_port
                        owns_current = self._driver_handle_value(
                            current_port
                        ) == self._driver_handle_value(owned_port)

                    if not owns_current:
                        break

                    receive_state, message = self._receive_driver_message(owned_port)

                    if receive_state != "message":
                        break

                    code = message.Data.MessageCode
                    pid = message.Data.ProcessId
                    target = message.Data.Path
                    exe_info = self.get_exe_info(pid)
                    safe_source = exe_info[1] if exe_info and exe_info[1] else "Unknown"

                    if not self.is_in_whitelist(safe_source):
                        self.write_log(
                            "BLOCK",
                            "Driver Block",
                            detail="Driver protection event",
                            pid=pid,
                            source=safe_source,
                            target=target,
                            code=code,
                            file_hash=self.calc_file_hash(safe_source),
                            operate=None,
                            success=True,
                        )

                self._close_driver_port(owned_port)
                owned_port = None
                ready = False
                self.driver_listener_ready_event.clear()

                if self.driver_stop_event.is_set():
                    break

                self.driver_stop_event.wait(0.02)

        except Exception as e:
            log_exception("PYAS_Driver.DriverMixin.pipe_server_thread:928")
            self.driver_listener_failed_event.set()

            if not self.driver_stop_event.is_set():
                self.write_log("WARN", "pipe_server_thread", detail=str(e), success=False)

        finally:
            if owned_port:
                try:
                    self.kernel32.CancelIoEx(owned_port, None)
                except Exception:
                    log_exception("PYAS_Driver.DriverMixin.pipe_server_thread:937")
                    pass

                self._close_driver_port(owned_port)

            if not ready and not self.driver_stop_event.is_set():
                self.driver_listener_failed_event.set()

            self.driver_listener_ready_event.clear()

            with self.lock_driver:
                if self.driver_listener_thread is threading.current_thread():
                    self.driver_listener_thread = None
