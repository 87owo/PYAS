from PYAS_Diagnostics import (
    log_exception,
    create_log_entry,
    is_ui_log_entry,
    MAX_LOG_ENTRIES,
)
import os
import time
import json
import uuid
import webview
from PYAS_Storage import atomic_write_json


class LogMixin:
    def load_logs(self):
        with self.lock_logs:
            pending_logs = list(self.logs_data)

            if os.path.exists(self.file_log):
                try:
                    with open(self.file_log, "r", encoding="utf-8") as f:
                        loaded_logs = json.load(f)

                    self.logs_data = (loaded_logs + pending_logs)[-MAX_LOG_ENTRIES:]
                except Exception:
                    log_exception("PYAS_Logs.LogMixin.load_logs:17")
                    self.logs_data = pending_logs

    def log_flush_thread(self):
        while not getattr(self, "closing", False):
            time.sleep(5)
            self.flush_logs_now()

    def write_log(
        self,
        level,
        action,
        detail=None,
        code=None,
        pid=None,
        file_hash=None,
        source=None,
        target=None,
        operate=None,
        success=True,
        ui_visible=None,
    ):
        entry = create_log_entry(
            level,
            action,
            detail,
            code,
            pid,
            file_hash,
            source,
            target,
            operate,
            success,
            ui_visible=ui_visible,
        )
        self._append_log_entry(entry)

        if level == "BLOCK" and self.tray_icon:
            self.trigger_block_notification(action, source, target, code)

    def _append_log_entry(self, entry):
        with self.lock_logs:
            self.logs_data.append(entry)

            if len(self.logs_data) > MAX_LOG_ENTRIES:
                del self.logs_data[:-MAX_LOG_ENTRIES]

            self.logs_dirty = True

            if self._window and is_ui_log_entry(entry):
                js_cmd = f"if(window.updateLogs) window.updateLogs({json.dumps(entry)});"
                self.ui_queue.put(js_cmd)

    def get_logs(self):
        with self.lock_logs:
            return [entry for entry in self.logs_data if is_ui_log_entry(entry)]

    def clear_logs(self, log_ids=None):
        with self.lock_logs:
            if log_ids is None:
                self.logs_data = []
            else:
                self.logs_data = [log for log in self.logs_data if log["id"] not in log_ids]

            try:
                if not self.logs_data:
                    if os.path.exists(self.file_log):
                        os.remove(self.file_log)
                else:
                    atomic_write_json(self.file_log, self.logs_data)

            except Exception:
                log_exception("PYAS_Logs.LogMixin.clear_logs:73")
                self.logs_dirty = True
                return False

            self.logs_dirty = False
            return True

    def export_logs(self, log_ids=None):
        if self._window:
            path = self._window.create_file_dialog(
                webview.FileDialog.SAVE, directory="", save_filename="PYAS_Logs.json"
            )

            if path:
                target_path = path[0] if isinstance(path, (tuple, list)) else path

                with self.lock_logs:
                    export_data = [entry for entry in self.logs_data if is_ui_log_entry(entry)]

                    if log_ids is not None:
                        export_data = [log for log in export_data if log["id"] in log_ids]

                    try:
                        with open(target_path, "w", encoding="utf-8") as f:
                            json.dump(export_data, f, indent=4, ensure_ascii=False)

                        return True
                    except Exception:
                        log_exception("PYAS_Logs.LogMixin.export_logs:95")
                        pass

        return False

    def flush_logs_now(self):
        with self.lock_logs:
            if not getattr(self, "logs_dirty", False):
                return True

            try:
                atomic_write_json(self.file_log, self.logs_data)
                self.logs_dirty = False
                return True
            except Exception:
                log_exception("PYAS_Logs.LogMixin.flush_logs_now:107")
                return False
