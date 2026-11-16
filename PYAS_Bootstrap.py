import ctypes
from ctypes import wintypes
import os
import sys
import time


PARENT_WINDOW_CLASS = "PyInstallerOnefileHiddenWindow"


class _ParentWindowAPI:
    def __init__(self):
        self.parent = None
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        self.kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
        ]
        self.kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        self.kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [
            ctypes.POINTER(wintypes.FILETIME)
        ] * 4
        self.kernel32.GetProcessTimes.restype = wintypes.BOOL
        self.kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel32.WaitForSingleObject.restype = wintypes.DWORD
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        self.user32.EnumWindows.argtypes = [self.callback_type, wintypes.LPARAM]
        self.user32.EnumWindows.restype = wintypes.BOOL
        self.user32.GetWindowThreadProcessId.argtypes = [
            wintypes.HWND, ctypes.POINTER(wintypes.DWORD)
        ]
        self.user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        self.user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        self.user32.GetClassNameW.restype = ctypes.c_int
        self.user32.SendMessageTimeoutW.argtypes = [
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
            wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t)
        ]
        self.user32.SendMessageTimeoutW.restype = ctypes.c_ssize_t

    def open_parent(self, pid):
        self.parent = self.kernel32.OpenProcess(0x00101000, False, pid)
        if not self.parent:
            raise ctypes.WinError(ctypes.get_last_error())

    def _image(self, handle):
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if not self.kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return os.path.normcase(os.path.realpath(buffer.value))

    def _created(self, handle):
        times = (wintypes.FILETIME * 4)()
        if not self.kernel32.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
            raise ctypes.WinError(ctypes.get_last_error())
        return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime

    def validate_parent(self):
        current = self.kernel32.GetCurrentProcess()
        if self._created(self.parent) > self._created(current):
            raise RuntimeError("Parent PID belongs to a newer process")
        return self._image(self.parent) == self._image(current)

    def parent_alive(self):
        result = self.kernel32.WaitForSingleObject(self.parent, 0)
        if result == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        return result == 0x102

    def matches(self, hwnd, parent_pid, thread_id=None):
        pid = wintypes.DWORD()
        thread = self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not thread or pid.value != parent_pid or (thread_id is not None and thread != thread_id):
            return False
        name = ctypes.create_unicode_buffer(256)
        if not self.user32.GetClassNameW(hwnd, name, len(name)):
            return False
        return name.value == PARENT_WINDOW_CLASS

    def find_windows(self, parent_pid):
        windows = []

        def collect(hwnd, unused):
            if self.matches(hwnd, parent_pid):
                thread = self.user32.GetWindowThreadProcessId(hwnd, None)
                windows.append((hwnd, thread))
            return True

        if not self.user32.EnumWindows(self.callback_type(collect), 0):
            raise ctypes.WinError(ctypes.get_last_error())
        return windows

    def request_close(self, hwnd, timeout_ms):
        result = ctypes.c_size_t()
        self.user32.SendMessageTimeoutW(hwnd, 0x0010, 0, 0, 3, timeout_ms, ctypes.byref(result))

    def release(self):
        if self.parent:
            self.kernel32.CloseHandle(self.parent)
            self.parent = None


def neutralize_onefile_parent(timeout=2.0):
    home = os.environ.get("_PYI_APPLICATION_HOME_DIR")
    extracted = getattr(sys, "_MEIPASS", None)
    if sys.platform != "win32" or not getattr(sys, "frozen", False) or not home or not extracted:
        return {"status": "not_applicable"}
    if os.path.normcase(os.path.realpath(home)) != os.path.normcase(os.path.realpath(extracted)):
        return {"status": "validation_failed", "reason": "Extraction directory mismatch"}
    parent_pid = os.getppid()
    if parent_pid <= 0 or parent_pid == os.getpid():
        return {"status": "validation_failed", "reason": "Invalid parent PID"}
    api = None
    try:
        api = _ParentWindowAPI()
        api.open_parent(parent_pid)
        if not api.validate_parent():
            return {"status": "not_applicable", "reason": "Parent uses a different executable"}
        deadline = time.monotonic() + max(0.0, timeout)
        while time.monotonic() < deadline:
            if not api.parent_alive():
                return {"status": "validation_failed", "reason": "Parent has exited"}
            windows = api.find_windows(parent_pid)
            if len(windows) > 1:
                return {"status": "validation_failed", "reason": "Ambiguous parent windows"}
            if windows:
                hwnd, thread = windows[0]
                if not api.matches(hwnd, parent_pid, thread):
                    return {"status": "validation_failed", "reason": "Window ownership changed"}
                remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
                api.request_close(hwnd, remaining_ms)
                while api.matches(hwnd, parent_pid, thread):
                    if time.monotonic() >= deadline:
                        return {"status": "timeout", "reason": "Parent window did not close"}
                    time.sleep(0.02)
                if not api.parent_alive():
                    return {"status": "validation_failed", "reason": "Parent exited during close"}
                return {"status": "closed", "parent_pid": parent_pid}
            time.sleep(0.02)
        return {"status": "timeout", "reason": "Parent window was not found"}
    except Exception as error:
        return {"status": "error", "reason": str(error)}
    finally:
        if api is not None:
            api.release()
