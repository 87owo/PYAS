from PYAS_Diagnostics import log_exception
import os
import threading
import ctypes
import ctypes.wintypes
from PYAS_WinAPI import SHQUERYRBINFO


class MaintenanceMixin:
    def _traverse_delete(self, path):
        deleted = 0

        if not path or not os.path.exists(path):
            return deleted

        try:
            items = os.listdir(path)
        except Exception:
            log_exception("PYAS_Maintenance.MaintenanceMixin._traverse_delete:16")
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
                        log_exception("PYAS_Maintenance.MaintenanceMixin._traverse_delete:29")
                        pass

                else:
                    if file.lower().endswith((".sys", ".dll", ".exe", ".ini", ".dat")):
                        continue

                    size = os.path.getsize(file)
                    os.remove(file)
                    deleted += size

            except Exception:
                log_exception("PYAS_Maintenance.MaintenanceMixin._traverse_delete:40")
                continue

        return deleted

    def _get_junk_dirs(self):
        return [
            self.path_temp,
            self.path_systemp,
            os.path.join(self.path_system, "SoftwareDistribution", "Download"),
        ]

    def _yield_log_files(self):
        log_dir = os.path.join(self.path_system, "Logs")

        if os.path.exists(log_dir):
            for root, _, files in os.walk(log_dir):
                for file in files:
                    if file.lower().endswith((".log", ".etl", ".evtx")):
                        yield os.path.join(root, file)

    def _get_recycle_bin_size(self):
        try:
            info = SHQUERYRBINFO()
            info.cbSize = ctypes.sizeof(SHQUERYRBINFO)

            if self.shell32.SHQueryRecycleBinW(None, ctypes.byref(info)) == 0 and info.i64Size > 0:
                return info.i64Size
        except Exception:
            log_exception("PYAS_Maintenance.MaintenanceMixin._get_recycle_bin_size:67")
            pass

        return 0

    def scan_system_junk(self):
        junk_list = []

        try:
            for path in self._get_junk_dirs():
                if os.path.exists(path):
                    for root, _, files in os.walk(path):
                        for file in files:
                            if not file.lower().endswith((".sys", ".dll", ".exe", ".ini", ".dat")):
                                try:
                                    fp = os.path.join(root, file)
                                    junk_list.append({"path": fp, "size": os.path.getsize(fp)})
                                except Exception:
                                    log_exception(
                                        "PYAS_Maintenance.MaintenanceMixin.scan_system_junk:83"
                                    )
                                    pass

            for fp in self._yield_log_files():
                try:
                    junk_list.append({"path": fp, "size": os.path.getsize(fp)})
                except Exception:
                    log_exception("PYAS_Maintenance.MaintenanceMixin.scan_system_junk:89")
                    pass

            rb_size = self._get_recycle_bin_size()

            if rb_size > 0:
                junk_list.append({"path": "Recycle Bin", "size": rb_size})

            return junk_list

        except Exception as e:
            log_exception("PYAS_Maintenance.MaintenanceMixin.scan_system_junk:98")
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

                    if path.lower().endswith((".sys", ".dll", ".exe", ".ini", ".dat")):
                        continue

                    try:
                        size = os.path.getsize(path)
                        os.remove(path)
                        total_deleted += size
                    except Exception:
                        log_exception("PYAS_Maintenance.MaintenanceMixin.clean_system_junk:120")
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
                        log_exception("PYAS_Maintenance.MaintenanceMixin.clean_system_junk:131")
                        pass

                rb_size = self._get_recycle_bin_size()

                if rb_size > 0 and self.shell32.SHEmptyRecycleBinW(None, None, 7) == 0:
                    total_deleted += rb_size

                try:
                    for log_type in ["Application", "Security", "Setup", "System"]:
                        log_path = os.path.join(
                            self.path_system, "System32", "winevt", "Logs", f"{log_type}.evtx"
                        )

                        size = os.path.getsize(log_path) if os.path.exists(log_path) else 0

                        if self._clear_event_log(log_type):
                            total_deleted += size

                except Exception:
                    log_exception("PYAS_Maintenance.MaintenanceMixin.clean_system_junk:146")
                    pass

            self.write_log(
                "INFO", "Clean Junk", detail=f"Deleted {total_deleted // 1024} KB", operate=True
            )
            return total_deleted

        except Exception as e:
            log_exception("PYAS_Maintenance.MaintenanceMixin.clean_system_junk:152")
            self.write_log("WARN", "clean_system_junk", detail=str(e), operate=True, success=False)
            return 0

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
                    "dwm.exe",
                    "explorer.exe",
                    "csrss.exe",
                    "smss.exe",
                    "winlogon.exe",
                    "lsass.exe",
                    "services.exe",
                    "svchost.exe",
                    "wininit.exe",
                    "audiodg.exe",
                    "spoolsv.exe",
                    "sihost.exe",
                    "fontdrvhost.exe",
                    "taskmgr.exe",
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
                            if self.kernel32.SetProcessWorkingSetSize(
                                h, ctypes.c_size_t(-1), ctypes.c_size_t(-1)
                            ):
                                optimized_count += 1
                        finally:
                            self.kernel32.CloseHandle(h)

                title = self._loc(
                    {
                        "traditional_switch": "一鍵加速",
                        "simplified_switch": "一键加速",
                        "english_switch": "Memory Boost",
                        "japanese_switch": "メモリ最適化",
                        "korean_switch": "메모리 최적화",
                        "french_switch": "Optimiser",
                        "spanish_switch": "Optimizar",
                        "hindi_switch": "मेमोरी बूस्ट",
                        "arabic_switch": "تسريع",
                        "russian_switch": "Ускорение",
                        "slovenian_switch": "Optimizacija",
                    }
                )

                msg = self._loc(
                    {
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
                        "slovenian_switch": f"Sproščen pomnilnik za {optimized_count} procesov v ozadju",
                    }
                )

                self.show_notification(title, msg)
                self.write_log(
                    "INFO",
                    "Memory Boost",
                    detail=f"Optimized {optimized_count} processes",
                    operate=True,
                )

            except Exception as e:
                log_exception("PYAS_Maintenance.MaintenanceMixin.optimize_memory._optimize:213")
                self.write_log("WARN", "optimize_memory", detail=str(e), success=False)

        threading.Thread(target=_optimize, daemon=True).start()
