import ctypes
import logging
import threading

import pystray
from pystray._util import win32


logger = logging.getLogger("PYAS.Tray")


class RetryingTrayIcon(pystray.Icon):
    RETRY_DELAYS = (0.5, 1.0, 2.0, 4.0, 8.0, 15.0)

    def __init__(self, *args, icon_loader=None, **kwargs):
        self._registration_lock = threading.RLock()
        self._retry_stop = threading.Event()
        self._retry_wake = threading.Event()
        self._registered = threading.Event()
        self._retry_started = False
        self._icon_loader = icon_loader
        super().__init__(*args, **kwargs)

    def run_detached(self):
        with self._registration_lock:
            if self._retry_started or self._retry_stop.is_set():
                return
            self._retry_started = True
            super().run_detached(setup=self._retry_registration)

    def _message(self, code, flags, **kwargs):
        with self._registration_lock:
            if self._retry_stop.is_set() and code != win32.NIM_DELETE:
                if code == win32.NIM_ADD:
                    raise OSError("Tray icon is stopping")
                return False
            data = win32.NOTIFYICONDATAW(
                cbSize=ctypes.sizeof(win32.NOTIFYICONDATAW),
                hWnd=self._hwnd, hID=id(self), uFlags=flags, **kwargs
            )
            accepted = bool(win32.Shell_NotifyIcon(code, data))
            if code == win32.NIM_ADD:
                if not accepted:
                    accepted = bool(win32.Shell_NotifyIcon(win32.NIM_MODIFY, data))
                if not accepted:
                    self._registered.clear()
                    raise OSError("Windows did not accept the tray icon registration")
                self._registered.set()
            elif code == win32.NIM_DELETE:
                self._registered.clear()
            elif not accepted and self._registered.is_set():
                self._registered.clear()
                self._visible = False
                self._retry_wake.set()
            return accepted

    def _retry_registration(self, icon):
        failures = 0
        while not self._retry_stop.is_set():
            with self._registration_lock:
                if self._retry_stop.is_set():
                    return
                if not self._registered.is_set():
                    try:
                        self._visible = False
                        if self.icon is None and self._icon_loader is not None:
                            self.icon = self._icon_loader()
                        self.visible = True
                        logger.info("Tray icon registered; previous failures=%s", failures)
                        failures = 0
                    except Exception:
                        if self._retry_stop.is_set():
                            return
                        failures += 1
                        if failures == 1 or failures % 10 == 0:
                            logger.warning("Tray registration failed; attempt=%s; retrying",
                                           failures, exc_info=True)
            delay = self.RETRY_DELAYS[min(failures - 1, len(self.RETRY_DELAYS) - 1)] if failures else 15.0
            self._retry_wake.wait(delay)
            self._retry_wake.clear()

    def _request_refresh(self):
        with self._registration_lock:
            if not self._retry_stop.is_set():
                self._registered.clear()
                self._visible = False
                self._retry_wake.set()

    def _on_taskbarcreated(self, wparam, lparam):
        self._request_refresh()

    def _on_display_change(self, wparam, lparam):
        self._request_refresh()

    def _mark_ready(self):
        super()._mark_ready()
        if self._retry_stop.is_set():
            self._stop()

    def stop(self):
        with self._registration_lock:
            if self._retry_stop.is_set():
                return
            self._retry_stop.set()
            self._retry_wake.set()
            if self._hwnd:
                try:
                    self._hide()
                except Exception:
                    logger.warning("Could not remove tray icon during shutdown", exc_info=True)
            self._visible = False
        super().stop()
