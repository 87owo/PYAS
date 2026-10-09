from PYAS_Diagnostics import log_exception
import os
import copy
import json
import threading
from PYAS_Storage import atomic_write_json


class ConfigMixin:
    def _loc(self, text_dict):
        with self.lock_config:
            lang = (
                self.pyas_config.get("language", "traditional_switch")
                if hasattr(self, "pyas_config")
                else "traditional_switch"
            )

        return text_dict.get(lang, text_dict.get("traditional_switch", ""))

    def load_config(self):
        with self.lock_config:

            if not os.path.exists(self.file_config):
                self.pyas_config = copy.deepcopy(self.pyas_default)
                self.write_log("INFO", "Config Update", detail="Create default config")
                self.save_config()

            else:
                try:
                    with open(self.file_config, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        self.pyas_config = copy.deepcopy(self.pyas_default)
                        self.pyas_config.update(data)

                    self.pyas_config["version"] = self.pyas_default["version"]
                    whitelist_metadata_updated = False

                    for item in self.pyas_config.get("white_list", []):
                        if not isinstance(item, dict) or not item.get("file") or "is_dir" in item:
                            continue

                        item_path = self.norm_path(item["file"], must_exist=False)

                        if item_path and os.path.exists(item_path):
                            item["is_dir"] = os.path.isdir(item_path)
                            whitelist_metadata_updated = True

                    if whitelist_metadata_updated:
                        self.save_config()
                except Exception as e:
                    log_exception("PYAS_Config.ConfigMixin.load_config:40")
                    self.pyas_config = copy.deepcopy(self.pyas_default)
                    self.write_log("WARN", "load_config", detail=str(e), success=False)

    def save_config(self):
        with self.lock_config:
            try:
                atomic_write_json(self.file_config, self.pyas_config)
                return True
            except Exception as error:
                log_exception("PYAS_Config.ConfigMixin.save_config:49")
                self.write_log("WARN", "save_config", detail=str(error), success=False)
                return False

    def update_config(self, key, value):
        with self.lock_update:
            with self.lock_config:
                old_value = self.pyas_config.get(key)

                if old_value == value:
                    return value

                defer_driver_disable = key == "driver_switch" and not value

                if not defer_driver_disable:
                    self.pyas_config[key] = value

            def apply_switch(state):
                if key == "cloud_switch":
                    with self.lock_config:
                        if state:
                            self.cloud_cancel_event = threading.Event()
                        else:
                            self.cloud_cancel_event.set()
                elif (
                    key in ("process_switch", "document_switch", "system_switch", "network_switch")
                    and state
                ):
                    target = {
                        "process_switch": self.protect_proc_thread,
                        "document_switch": self.protect_file_thread,
                        "system_switch": self.protect_system_thread,
                        "network_switch": self.protect_net_thread,
                    }[key]
                    self.start_feature_thread(target, key)
                elif key == "driver_switch":
                    if state:
                        if self.install_system_driver() and self.start_driver_listener(
                            wait_ready=True
                        ):
                            return True

                        self.stop_system_driver()
                        return False

                    return bool(self.stop_system_driver())
                elif key == "context_switch":
                    return self.register_context_menu(state) is not False
                elif key == "autostart_switch":
                    return bool(self.manage_autostart(state))
                elif key == "document_switch" and not state:
                    self._cancel_pending_file_scans()

                    with self.lock_file_ops:
                        if getattr(self, "h_dir_file", None):
                            if not self.kernel32.CloseHandle(self.h_dir_file):
                                raise OSError("Could not close directory watcher")

                            self.h_dir_file = None
                elif key == "suspend_switch" and not state:
                    with self.lock_proc:
                        for handle in list(getattr(self, "suspended_procs", ())):
                            if self.ntdll.NtResumeProcess(handle) != 0:
                                raise OSError("Could not resume suspended process")

                            self.suspended_procs.discard(handle)

                return True

            action_succeeded = False

            try:
                if key in ("extension_switch", "sensitive_switch"):
                    with self.lock_file_ops:
                        self.hash_cache.clear()

                action_succeeded = apply_switch(value)

                if not action_succeeded:
                    raise RuntimeError(f"Could not apply {key}")

                with self.lock_config:
                    self.pyas_config[key] = value

                    if self.save_config() is False:
                        raise OSError("Could not persist configuration")

                self.write_log("INFO", "Config Update", detail=f"[{key}] {old_value} -> {value}")

                if key == "language" and self.tray_icon:
                    try:
                        self.tray_icon.update_menu()
                    except Exception:
                        log_exception("PYAS_Config.ConfigMixin.update_config:116")
                        pass

                return value
            except Exception as error:
                log_exception("PYAS_Config.ConfigMixin.update_config:119")
                self.write_log("WARN", "Config Update", detail=f"[{key}] {error}", success=False)

                with self.lock_config:
                    self.pyas_config[key] = old_value

                if action_succeeded:
                    try:
                        if apply_switch(old_value) is False:
                            raise RuntimeError(f"Could not roll back {key}")
                    except Exception as rollback_error:
                        log_exception("PYAS_Config.ConfigMixin.update_config:127")
                        self.write_log(
                            "WARN",
                            "Config Rollback",
                            detail=f"[{key}] {rollback_error}",
                            success=False,
                        )

                        if key == "driver_switch":
                            with self.lock_config:
                                self.pyas_config[key] = bool(self.check_system_driver())

                if self._window:
                    try:
                        self._window.evaluate_js(
                            f"if(window.revertSwitch) window.revertSwitch({json.dumps(key)});"
                        )
                    except Exception:
                        log_exception("PYAS_Config.ConfigMixin.update_config:135")
                        pass

                return self.pyas_config.get(key, old_value)

    def get_config(self):
        with self.lock_config:
            cfg = self.pyas_config.copy()
            cfg["autostart_mode"] = self.autostart_mode

            rules = []

            if os.path.exists(self.path_rules):
                for f in os.listdir(self.path_rules):
                    if f.lower().endswith(".json"):
                        fp = os.path.join(self.path_rules, f)
                        rules.append({"file": fp, "time": os.path.getmtime(fp)})

            cfg["custom_rule"] = rules
            return cfg

    def reset_config(self):
        with self.lock_update:
            with self.lock_config:
                previous = self.pyas_config
                self.pyas_config = copy.deepcopy(self.pyas_default)

                if self.save_config() is False:
                    self.pyas_config = previous
                    return False

                self.write_log("INFO", "Config Update", detail="Reset to default")

        return True
