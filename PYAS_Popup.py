from PYAS_Diagnostics import log_exception
import time
import copy
import ctypes
import ctypes.wintypes
from PYAS_WinAPI import POINT, RECT
import os
import uuid
import math


def normalized_path(path):
    return os.path.normcase(os.path.normpath(path)) if isinstance(path, str) and path else ""


def signature_matches(expected, actual):
    if not isinstance(expected, dict) or not isinstance(actual, dict):
        return False

    for key in ("class", "style", "exstyle", "children", "owner"):
        if key not in expected or expected[key] != actual.get(key):
            return False

    for key in ("width", "height"):
        size = expected.get(key)
        current = actual.get(key)

        if not isinstance(size, (int, float)) or not isinstance(current, (int, float)):
            return False

        if (
            not math.isfinite(size)
            or not math.isfinite(current)
            or size <= 0
            or current <= 0
            or abs(size - current) > max(8, size * 0.08)
        ):
            return False

    return True


def is_main_anchor(window, target):
    return (
        window.get("hwnd") != target.get("hwnd")
        and window.get("pid") == target.get("pid")
        and normalized_path(window.get("path")) == normalized_path(target.get("path"))
        and not window.get("fingerprint", {}).get("owner")
        and not window.get("fingerprint", {}).get("exstyle", 0) & 0x80
        and window.get("fingerprint", {}).get("style", 0) & 0x00030000 == 0x00030000
        and window.get("fingerprint", {}).get("width", 0)
        * window.get("fingerprint", {}).get("height", 0)
        > target.get("fingerprint", {}).get("width", 0)
        * target.get("fingerprint", {}).get("height", 0)
        * 1.25
    )


def secondary_candidate(target):
    fingerprint = target.get("fingerprint", {})
    return bool(
        fingerprint.get("owner")
        or fingerprint.get("exstyle", 0) & 0x80
        or not fingerprint.get("style", 0) & 0x00030000
    )


def build_popup_rule(target, windows):
    if not target or not target.get("path") or not target.get("fingerprint", {}).get("class"):
        return None

    fingerprint = target["fingerprint"]
    peers = [
        window
        for window in windows
        if window.get("pid") == target.get("pid")
        and normalized_path(window.get("path")) == normalized_path(target.get("path"))
        and window["hwnd"] != target["hwnd"]
    ]
    identical = any(
        all(
            fingerprint.get(key) == window.get("fingerprint", {}).get(key)
            for key in ("class", "style", "exstyle", "children", "owner")
        )
        for window in peers
    )
    anchors = [window for window in peers if is_main_anchor(window, target)]
    distinctive = secondary_candidate(target) or bool(anchors)
    mode = (
        "adaptive"
        if isinstance(fingerprint.get("children"), list)
        and signature_matches(fingerprint, fingerprint)
        and distinctive
        and not identical
        and not target.get("modal")
        else "title"
    )
    return {
        "id": uuid.uuid4().hex,
        "schema_version": 2,
        "exe": target["exe"],
        "path": target["path"],
        "class": fingerprint["class"],
        "title": target.get("title", ""),
        "fingerprint": fingerprint,
        "match_mode": mode,
        "protected": [
            window["fingerprint"]
            for window in peers
            if not signature_matches(fingerprint, window.get("fingerprint"))
        ],
    }


def popup_rule_matches(rule, target, windows):
    if not isinstance(rule, dict) or not target:
        return False

    if rule.get("schema_version") != 2:
        return bool(
            rule.get("exe") == target.get("exe")
            and rule.get("class") == target.get("fingerprint", {}).get("class")
            and rule.get("title")
            and rule["title"] == target.get("title")
            and not target.get("modal")
        )

    if (
        not rule.get("id")
        or not normalized_path(rule.get("path"))
        or normalized_path(rule["path"]) != normalized_path(target.get("path"))
    ):
        return False

    fingerprint = target.get("fingerprint", {})

    if not rule.get("class") or rule["class"] != fingerprint.get("class"):
        return False

    if any(signature_matches(protected, fingerprint) for protected in rule.get("protected", [])):
        return False

    expected = rule.get("fingerprint", {})
    structural_match = signature_matches(expected, fingerprint)
    title_match = bool(rule.get("title") and rule["title"] == target.get("title"))

    if rule.get("match_mode", "adaptive") == "title":
        if not title_match or not all(
            expected.get(key) == fingerprint.get(key) for key in ("style", "exstyle", "owner")
        ):
            return False

        return not any(
            window.get("hwnd") != target.get("hwnd")
            and window.get("pid") == target.get("pid")
            and normalized_path(window.get("path")) == normalized_path(target.get("path"))
            and window.get("title") == target.get("title")
            and window.get("fingerprint", {}).get("class") == rule["class"]
            and all(
                window.get("fingerprint", {}).get(key) == fingerprint.get(key)
                for key in ("style", "exstyle", "owner")
            )
            for window in windows
        )

    if not structural_match or target.get("modal"):
        return False

    peers = [
        window
        for window in windows
        if window.get("pid") == target.get("pid")
        and normalized_path(window.get("path")) == normalized_path(target.get("path"))
        and window["hwnd"] != target["hwnd"]
    ]
    identical = [
        window for window in peers if signature_matches(expected, window.get("fingerprint"))
    ]

    if identical:
        return title_match and not any(
            window.get("title") == target.get("title") for window in identical
        )

    return True


class PopupWindowMixin:
    def capture_popup_window(self):
        self._init_popup_api()
        overlay = self.user32.CreateWindowExW(
            0x000800A8, "STATIC", "", 0x98000004, 0, 0, 0, 0, None, None, None, None
        )

        if overlay:
            self.user32.SetLayeredWindowAttributes(overlay, 0, 120, 2)

        target_hwnd = None
        last_hwnd = None
        msg = ctypes.wintypes.MSG()

        start_time = time.monotonic()

        try:
            while self.user32.GetAsyncKeyState(0x01) & 0x8000:
                if time.monotonic() - start_time >= 30:
                    return None

                time.sleep(0.01)

            while time.monotonic() - start_time < 30:
                if self.user32.GetAsyncKeyState(0x1B) & 0x8000:
                    break

                pt = POINT()
                self.user32.GetCursorPos(ctypes.byref(pt))

                hwnd = self.user32.WindowFromPoint(pt)
                root_hwnd = self.user32.GetAncestor(hwnd, 2)

                if not root_hwnd:
                    root_hwnd = hwnd

                if root_hwnd and root_hwnd != overlay:
                    if root_hwnd != last_hwnd:
                        last_hwnd = root_hwnd
                        rect = RECT()
                        self.user32.GetWindowRect(root_hwnd, ctypes.byref(rect))
                        self.user32.SetWindowPos(
                            overlay,
                            -1,
                            rect.left,
                            rect.top,
                            rect.right - rect.left,
                            rect.bottom - rect.top,
                            0x0050,
                        )

                    if self.user32.GetAsyncKeyState(0x01) & 0x8000:
                        target_hwnd = root_hwnd
                        break

                while self.user32.PeekMessageW(ctypes.byref(msg), 0, 0, 0, 1):
                    self.user32.TranslateMessage(ctypes.byref(msg))
                    self.user32.DispatchMessageW(ctypes.byref(msg))

                time.sleep(0.02)
        finally:
            if overlay:
                self.user32.DestroyWindow(overlay)

        if not target_hwnd:
            return None

        pid = ctypes.c_ulong(0)
        self.user32.GetWindowThreadProcessId(target_hwnd, ctypes.byref(pid))

        if pid.value != self.pid_pyas and pid.value > 4:
            length = self.user32.GetWindowTextLengthW(target_hwnd)
            title = ctypes.create_unicode_buffer(length + 1)
            class_name = ctypes.create_unicode_buffer(256)

            self.user32.GetWindowTextW(target_hwnd, title, length + 1)
            self.user32.GetClassNameW(target_hwnd, class_name, 256)

            proc_name, _ = self.get_exe_info(pid.value)
            t_str, c_str = str(title.value), str(class_name.value)

            if proc_name and not any(
                item.get("exe") == proc_name or item.get("class") == c_str
                for item in self.pass_windows
            ):
                target = self._popup_window_snapshot(target_hwnd)
                windows = self._popup_windows({normalized_path(target["path"])}) if target else []
                rule = build_popup_rule(target, windows)

                if not rule:
                    return {"error": "popup_capture_failed"}

                token = (time.monotonic_ns() & 0x7FFFFFFF) or 1
                selected = {"hwnd": target_hwnd, "pid": target["pid"], "token": token}

                if not self.user32.SetPropW(target_hwnd, "PYAS_Popup_Selected", token):
                    return {"error": "popup_capture_failed"}

                with self.lock_config:
                    previous = getattr(self, "_popup_selected", {})
                    active = {
                        item.get("id")
                        for item in self.pyas_config.get("block_list", [])
                        if isinstance(item, dict)
                    }

                    for identifier, record in list(previous.items()):
                        if identifier not in active:
                            if (
                                self.user32.GetPropW(record["hwnd"], "PYAS_Popup_Selected")
                                == record["token"]
                            ):
                                self.user32.RemovePropW(record["hwnd"], "PYAS_Popup_Selected")

                            previous.pop(identifier, None)

                    previous[rule["id"]] = selected
                    self._popup_selected = previous
                    self._captured_popup_rules = {rule["id"]: copy.deepcopy(rule)}

                return rule

        return {"error": "popup_capture_failed"}

    def _init_popup_api(self):
        if getattr(self, "_popup_api_ready", False):
            return

        self._popup_enum_type = ctypes.WINFUNCTYPE(
            ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM
        )
        self.user32.CreateWindowExW.argtypes = [
            ctypes.wintypes.DWORD,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.wintypes.HWND,
            ctypes.wintypes.HMENU,
            ctypes.wintypes.HINSTANCE,
            ctypes.c_void_p,
        ]
        self.user32.CreateWindowExW.restype = ctypes.wintypes.HWND
        self.user32.DestroyWindow.argtypes = [ctypes.wintypes.HWND]
        self.user32.DestroyWindow.restype = ctypes.wintypes.BOOL
        self.user32.PeekMessageW.argtypes = [
            ctypes.POINTER(ctypes.wintypes.MSG),
            ctypes.wintypes.HWND,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
        ]
        self.user32.PeekMessageW.restype = ctypes.wintypes.BOOL
        self.user32.TranslateMessage.argtypes = [ctypes.POINTER(ctypes.wintypes.MSG)]
        self.user32.TranslateMessage.restype = ctypes.wintypes.BOOL
        self.user32.DispatchMessageW.argtypes = [ctypes.POINTER(ctypes.wintypes.MSG)]
        self.user32.DispatchMessageW.restype = ctypes.wintypes.LPARAM

        for name in ("EnumWindows", "EnumChildWindows"):
            function = getattr(self.user32, name)
            function.argtypes = (
                [self._popup_enum_type, ctypes.wintypes.LPARAM]
                if name == "EnumWindows"
                else [ctypes.wintypes.HWND, self._popup_enum_type, ctypes.wintypes.LPARAM]
            )
            function.restype = ctypes.wintypes.BOOL

        self._popup_get_style = getattr(
            self.user32, "GetWindowLongPtrW", self.user32.GetWindowLongW
        )
        self._popup_get_style.argtypes = [ctypes.wintypes.HWND, ctypes.c_int]
        self._popup_get_style.restype = ctypes.c_ssize_t

        for name in ("IsWindow", "IsWindowVisible", "IsWindowEnabled", "IsIconic"):
            function = getattr(self.user32, name)
            function.argtypes = [ctypes.wintypes.HWND]
            function.restype = ctypes.wintypes.BOOL

        self.user32.GetWindow.argtypes = [ctypes.wintypes.HWND, ctypes.c_uint]
        self.user32.GetWindow.restype = ctypes.wintypes.HWND
        self.user32.GetClientRect.argtypes = [ctypes.wintypes.HWND, ctypes.POINTER(RECT)]
        self.user32.GetClientRect.restype = ctypes.wintypes.BOOL

        class WINDOWPLACEMENT(ctypes.Structure):
            _fields_ = [
                ("length", ctypes.wintypes.DWORD),
                ("flags", ctypes.wintypes.DWORD),
                ("showCmd", ctypes.wintypes.DWORD),
                ("ptMinPosition", POINT),
                ("ptMaxPosition", POINT),
                ("rcNormalPosition", RECT),
            ]

        self._popup_placement_type = WINDOWPLACEMENT
        self.user32.GetWindowPlacement.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.POINTER(WINDOWPLACEMENT),
        ]
        self.user32.GetWindowPlacement.restype = ctypes.wintypes.BOOL
        self.user32.GetWindowThreadProcessId.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.POINTER(ctypes.wintypes.DWORD),
        ]
        self.user32.GetWindowThreadProcessId.restype = ctypes.wintypes.DWORD
        self.user32.GetWindowTextLengthW.argtypes = [ctypes.wintypes.HWND]
        self.user32.GetWindowTextLengthW.restype = ctypes.c_int
        self.user32.GetWindowTextW.argtypes = [ctypes.wintypes.HWND, ctypes.c_wchar_p, ctypes.c_int]
        self.user32.GetClassNameW.argtypes = [ctypes.wintypes.HWND, ctypes.c_wchar_p, ctypes.c_int]
        self.user32.ShowWindowAsync.argtypes = [ctypes.wintypes.HWND, ctypes.c_int]
        self.user32.ShowWindowAsync.restype = ctypes.wintypes.BOOL
        self.user32.SetPropW.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.c_wchar_p,
            ctypes.wintypes.HANDLE,
        ]
        self.user32.SetPropW.restype = ctypes.wintypes.BOOL
        self.user32.GetPropW.argtypes = [ctypes.wintypes.HWND, ctypes.c_wchar_p]
        self.user32.GetPropW.restype = ctypes.wintypes.HANDLE
        self.user32.RemovePropW.argtypes = [ctypes.wintypes.HWND, ctypes.c_wchar_p]
        self.user32.RemovePropW.restype = ctypes.wintypes.HANDLE

        if hasattr(self.user32, "GetDpiForWindow"):
            self.user32.GetDpiForWindow.argtypes = [ctypes.wintypes.HWND]
            self.user32.GetDpiForWindow.restype = ctypes.c_uint

        self._popup_api_ready = True

    def _popup_window_snapshot(self, hwnd, process_info=None):
        if not self.user32.IsWindow(hwnd):
            return None

        pid = ctypes.wintypes.DWORD()
        self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))

        if pid.value <= 4 or pid.value == self.pid_pyas:
            return None

        process_info = {} if process_info is None else process_info

        if pid.value not in process_info:
            process_info[pid.value] = self.get_exe_info(pid.value)

        exe, path = process_info[pid.value]

        if not exe or not path:
            return None

        class_name = ctypes.create_unicode_buffer(256)

        if not self.user32.GetClassNameW(hwnd, class_name, 256):
            return None

        if any(
            item.get("exe") == exe or item.get("class") == class_name.value
            for item in self.pass_windows
        ):
            return None

        rect = RECT()

        if not self.user32.GetClientRect(hwnd, ctypes.byref(rect)):
            self.user32.GetWindowRect(hwnd, ctypes.byref(rect))

        if self.user32.IsIconic(hwnd):
            placement = self._popup_placement_type()
            placement.length = ctypes.sizeof(placement)

            if self.user32.GetWindowPlacement(hwnd, ctypes.byref(placement)):
                rect = placement.rcNormalPosition

        dpi = self.user32.GetDpiForWindow(hwnd) if hasattr(self.user32, "GetDpiForWindow") else 96
        dpi = dpi or 96
        classes = {}
        child_count = 0

        def enum_child(child, parameter):
            nonlocal child_count
            child_count += 1

            if child_count > 128:
                return False

            name = ctypes.create_unicode_buffer(256)

            if not self.user32.GetClassNameW(child, name, 256):
                child_count = 129
                return False

            classes[name.value] = classes.get(name.value, 0) + 1
            return True

        callback = self._popup_enum_type(enum_child)
        self.user32.EnumChildWindows(hwnd, callback, 0)
        children = (
            None
            if child_count > 128
            else [[name, count] for name, count in sorted(classes.items())]
        )
        owner_hwnd = self.user32.GetWindow(hwnd, 4)
        owner = None

        if owner_hwnd:
            owner_pid = ctypes.wintypes.DWORD()
            self.user32.GetWindowThreadProcessId(owner_hwnd, ctypes.byref(owner_pid))

            if owner_pid.value not in process_info:
                process_info[owner_pid.value] = self.get_exe_info(owner_pid.value)

            _, owner_path = process_info[owner_pid.value]
            owner_class = ctypes.create_unicode_buffer(256)
            self.user32.GetClassNameW(owner_hwnd, owner_class, 256)
            owner = {"path": normalized_path(owner_path), "class": owner_class.value}

        title = ctypes.create_unicode_buffer(min(self.user32.GetWindowTextLengthW(hwnd), 4096) + 1)
        self.user32.GetWindowTextW(hwnd, title, len(title))
        return {
            "hwnd": hwnd,
            "pid": pid.value,
            "exe": exe,
            "path": path,
            "title": title.value,
            "visible": bool(self.user32.IsWindowVisible(hwnd)),
            "minimized": bool(self.user32.IsIconic(hwnd)),
            "modal": bool(owner_hwnd and not self.user32.IsWindowEnabled(owner_hwnd)),
            "fingerprint": {
                "class": class_name.value,
                "style": self._popup_get_style(hwnd, -16) & 0x80CF0000,
                "exstyle": self._popup_get_style(hwnd, -20) & 0x08040088,
                "width": round((rect.right - rect.left) * 96 / dpi),
                "height": round((rect.bottom - rect.top) * 96 / dpi),
                "children": children,
                "owner": owner,
            },
        }

    def _popup_windows(self, paths=None):
        self._init_popup_api()
        windows = []
        process_info = {}

        def enum_window(hwnd, parameter):
            try:
                if paths is not None:
                    pid = ctypes.wintypes.DWORD()
                    self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))

                    if pid.value not in process_info:
                        process_info[pid.value] = self.get_exe_info(pid.value)

                    if normalized_path(process_info[pid.value][1]) not in paths:
                        return True

                snapshot = self._popup_window_snapshot(hwnd, process_info)

                if snapshot:
                    windows.append(snapshot)
            except Exception:
                log_exception("PYAS_Popup.PopupWindowMixin._popup_windows.enum_window:246")
                return True

            return True

        callback = self._popup_enum_type(enum_window)
        self.user32.EnumWindows(callback, 0)
        return windows

    def add_popup_rule(self, rule):
        if not isinstance(rule, dict) or rule.get("schema_version") != 2 or not rule.get("id"):
            return False

        with self.lock_config:
            pending = getattr(self, "_captured_popup_rules", {})
            captured = pending.get(rule["id"])

            if captured != rule:
                return any(item == rule for item in self.pyas_config.get("block_list", []))

            target_list = self.pyas_config.setdefault("block_list", [])
            duplicate = next(
                (
                    item
                    for item in target_list
                    if isinstance(item, dict)
                    and item.get("schema_version") == 2
                    and normalized_path(item.get("path")) == normalized_path(rule.get("path"))
                    and item.get("fingerprint") == rule.get("fingerprint")
                    and item.get("title") == rule.get("title")
                    and item.get("match_mode") == rule.get("match_mode")
                ),
                None,
            )

            if duplicate:
                selected = getattr(self, "_popup_selected", {}).pop(rule["id"], None)

                if selected:
                    self._popup_selected[duplicate["id"]] = selected
            else:
                target_list.append(copy.deepcopy(captured))
                self.save_config()
                self.write_log(
                    "INFO",
                    "Config Update",
                    detail=f"Popup rule added: {rule['exe']} [{rule['id']}]",
                )

            pending.pop(rule["id"], None)
            return True

    def _popup_matches(self, rule, target, windows):
        with self.lock_config:
            selected = getattr(self, "_popup_selected", {}).get(rule.get("id"))

        if (
            selected
            and selected["hwnd"] == target.get("hwnd")
            and selected["pid"] == target.get("pid")
        ):
            if self.user32.GetPropW(selected["hwnd"], "PYAS_Popup_Selected") == selected["token"]:
                return normalized_path(rule.get("path")) == normalized_path(target.get("path"))

        return popup_rule_matches(rule, target, windows)

    def remove_popup_rules(self, identifiers):
        with self.lock_config:
            rules = self.pyas_config.get("block_list", [])
            identifiers = set(identifiers or [])
            remaining = [
                rule
                for index, rule in enumerate(rules)
                if (rule.get("id") or f"legacy:{index}") not in identifiers
            ]

            if len(remaining) == len(rules):
                return False

            selected = getattr(self, "_popup_selected", {})

            for identifier in identifiers:
                record = selected.pop(identifier, None)

                if (
                    record
                    and self.user32.GetPropW(record["hwnd"], "PYAS_Popup_Selected")
                    == record["token"]
                ):
                    self.user32.RemovePropW(record["hwnd"], "PYAS_Popup_Selected")

            self.pyas_config["block_list"] = remaining
            self.write_log(
                "INFO",
                "Config Update",
                detail=f"Popup rules removed: {len(rules) - len(remaining)}",
            )
            self.save_config()
            return True

    def _restore_popup_windows(self, hidden, active_ids):
        for hwnd, record in list(hidden.items()):
            if self.user32.GetPropW(hwnd, "PYAS_Popup_Blocker") != record["token"]:
                hidden.pop(hwnd, None)
            elif record["rule_id"] not in active_ids:
                self.user32.RemovePropW(hwnd, "PYAS_Popup_Blocker")
                self.user32.ShowWindowAsync(hwnd, 4)
                hidden.pop(hwnd, None)

    def _hide_popup_window(self, rule, target, windows, hidden):
        hwnd = target["hwnd"]
        current = self._popup_window_snapshot(hwnd)

        if (
            not current
            or current["pid"] != target["pid"]
            or not self._popup_matches(rule, current, windows)
        ):
            return False

        record = hidden.get(hwnd)
        new_record = (
            not record or self.user32.GetPropW(hwnd, "PYAS_Popup_Blocker") != record["token"]
        )

        if new_record:
            token = (time.monotonic_ns() & 0x7FFFFFFF) or 1

            if not self.user32.SetPropW(hwnd, "PYAS_Popup_Blocker", token):
                return False

            record = {"token": token, "rule_id": rule["id"]}
            hidden[hwnd] = record

        if not self.user32.ShowWindowAsync(hwnd, 0):
            if new_record:
                self.user32.RemovePropW(hwnd, "PYAS_Popup_Blocker")
                hidden.pop(hwnd, None)

            return False

        return True

    def popup_intercept_thread(self):
        hidden = {}
        last_warning = {}

        while True:
            try:
                time.sleep(0.5)
                self._init_popup_api()

                with self.lock_config:
                    rules = copy.deepcopy(self.pyas_config.get("block_list", []))

                valid_rules = []

                for index, rule in enumerate(rules):
                    if isinstance(rule, dict) and (
                        rule.get("schema_version") == 2
                        and rule.get("id")
                        or rule.get("exe")
                        and rule.get("class")
                        and rule.get("title")
                    ):
                        rule.setdefault("id", f"legacy:{index}")
                        valid_rules.append(rule)

                self._restore_popup_windows(hidden, {rule["id"] for rule in valid_rules})

                if not valid_rules:
                    continue

                paths = {normalized_path(rule.get("path")) for rule in valid_rules}
                windows = self._popup_windows(paths if all(paths) else None)

                for target in windows:
                    if not target.get("visible") or target.get("minimized"):
                        continue

                    for rule in valid_rules:
                        if self._popup_matches(rule, target, windows):
                            first_hide = target["hwnd"] not in hidden

                            if self._hide_popup_window(rule, target, windows, hidden):
                                if first_hide:
                                    self.write_log(
                                        "INFO",
                                        "Popup Blocker",
                                        source=target["path"],
                                        detail=f"Hidden popup window: {target['title']}",
                                        pid=target["pid"],
                                    )
                            elif first_hide:
                                key = (rule["id"], target["hwnd"], target["pid"])
                                now = time.monotonic()

                                if now - last_warning.get(key, -30) >= 30:
                                    self.write_log(
                                        "WARN",
                                        "Popup Blocker",
                                        source=target["path"],
                                        detail="Unable to hide selected window",
                                        pid=target["pid"],
                                        success=False,
                                    )
                                    last_warning[key] = now

                            break
            except Exception as e:
                log_exception("PYAS_Popup.PopupWindowMixin.popup_intercept_thread:369")
                now = time.monotonic()

                if now - last_warning.get("error", -30) >= 30:
                    self.write_log("WARN", "Popup Blocker", detail=str(e), success=False)
                    last_warning["error"] = now
