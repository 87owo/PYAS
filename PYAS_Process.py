from PYAS_Diagnostics import log_exception
import os
import re
import io
import time
import ctypes
import ctypes.wintypes
from PYAS_WinAPI import (
    IO_COUNTERS,
    MIB_TCPROW_OWNER_PID,
    PROCESSENTRY32W,
    PROCESS_BASIC_INFORMATION,
    PYAS_PROCESS_TERMINATE_ACCESS,
    UNICODE_STRING,
)


class ProcessMixin:
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
        try:
            pbi = PROCESS_BASIC_INFORMATION()
            returned = ctypes.wintypes.ULONG()

            if (
                self.ntdll.NtQueryInformationProcess(
                    h, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(returned)
                )
                != 0
            ):
                return ""

            if returned.value != ctypes.sizeof(pbi) or not pbi.PebBaseAddress:
                return ""

            def read_exact(address, destination):
                transferred = ctypes.c_size_t()
                capacity = ctypes.sizeof(destination)
                return (
                    bool(
                        self.kernel32.ReadProcessMemory(
                            h,
                            ctypes.c_void_p(address),
                            ctypes.byref(destination),
                            capacity,
                            ctypes.byref(transferred),
                        )
                    )
                    and transferred.value == capacity
                )

            pointer_size = ctypes.sizeof(ctypes.c_void_p)
            parameters = ctypes.c_void_p()

            if (
                not read_exact(
                    int(pbi.PebBaseAddress) + (0x20 if pointer_size == 8 else 0x10), parameters
                )
                or not parameters.value
            ):
                return ""

            descriptor = UNICODE_STRING()

            if not read_exact(parameters.value + (0x70 if pointer_size == 8 else 0x40), descriptor):
                return ""

            length = int(descriptor.Length)

            if not descriptor.Buffer or not length:
                return ""

            if length % 2 or length > descriptor.MaximumLength:
                raise ValueError("Invalid remote UTF-16 command-line length")

            buffer = (ctypes.c_ubyte * length)()

            if not read_exact(int(descriptor.Buffer), buffer):
                return ""

            return bytes(buffer).decode("utf-16-le", errors="surrogatepass")
        except Exception:
            log_exception("ProcessMixin.get_process_cmdline")
            return ""

    def extract_paths_from_cmdline(self, cmdline):
        if not cmdline:
            return []

        found = []

        for m in re.finditer(r'"([^"]+)"|\'([^\']+)\'', cmdline):
            path = m.group(1) or m.group(2)

            if re.match(r"^[A-Za-z]:\\|^\\\\", path):
                found.append(path)

        if not found:
            m = re.search(
                r'([A-Za-z]:\\[^\*?"<>\|]+\.(?:exe|dll|bat|cmd|vbs|sys|com|pif))',
                cmdline,
                re.IGNORECASE,
            )

            if m:
                found.append(m.group(1))

        if not found:
            argc = ctypes.c_int(0)
            argv = self.shell32.CommandLineToArgvW(cmdline, ctypes.byref(argc))

            if argv:
                args = [argv[i] for i in range(argc.value)]
                self.kernel32.LocalFree(ctypes.cast(argv, ctypes.c_void_p))
                patterns = [
                    r'([A-Za-z]:\\[^"\']+)',
                    r'(\\\\[^"\']+)',
                    r'(\.\\[^"\']+)',
                    r'(\./[^"\']+)',
                    r'([A-Za-z]:/[^"\']+)',
                    r"([^\s]*\\[^\s]+)",
                ]

                for arg in args:
                    for p in patterns:
                        for match in re.finditer(p, arg):
                            found.append(match.group(1).strip('"').strip("'"))

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
                    log_exception("PYAS_Process.ProcessMixin.get_process_list:140")
                    name = "Unknown"

            result.append({"pid": pid, "name": name, "path": file_path or "None"})

        return result

    def get_process_list_pids(self):
        return {pid for pid, _ in self._enum_processes()}

    def kill_process(self, pid, expected_path=None):
        try:
            h = self.kernel32.OpenProcess(PYAS_PROCESS_TERMINATE_ACCESS, False, pid)

            if h:
                try:
                    return self._terminate_process_handle(h, pid=pid, expected_path=expected_path)
                finally:
                    self.kernel32.CloseHandle(h)

        except Exception as e:
            log_exception("PYAS_Process.ProcessMixin.kill_process:159")
            self.write_log(
                "WARN", "kill_process", pid=pid, detail=str(e), operate=True, success=False
            )

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
                row = MIB_TCPROW_OWNER_PID.from_address(
                    ctypes.addressof(buf)
                    + ctypes.sizeof(ctypes.wintypes.DWORD)
                    + i * ctypes.sizeof(MIB_TCPROW_OWNER_PID)
                )
                connections.add((row.dwOwningPid, row.dwRemoteAddr, row.dwRemotePort))

        except Exception:
            log_exception("PYAS_Process.ProcessMixin.get_connections_list:179")
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
                result.append(
                    {
                        "pid": pid,
                        "name": name,
                        "path": file_path or "None",
                        "down": int(down_speed),
                        "up": int(up_speed),
                        "conn": count,
                    }
                )

        with self.lock_io:
            self.last_io_counters = current_io

        return result

    def _terminate_process_handle(self, handle, pid=None, expected_path=None):
        file_path = self.norm_path(self.get_process_file(handle))

        if self.path_equal(file_path, self.file_pyas):
            return False

        if expected_path and not self.path_equal(file_path, expected_path):
            return False

        return bool(self.kernel32.TerminateProcess(handle, 0))
