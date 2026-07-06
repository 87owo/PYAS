import os, gc, json, time, stat, threading
import ctypes, ctypes.wintypes

from PYAS_Tools import MEMORY_BASIC_INFORMATION

####################################################################################################

class ScannerMixin:
    def init_engine_thread(self):
        try:
            self.start_daemon_thread(self.backup_mbr)
            self.start_daemon_thread(self.relock_file)
            self.start_daemon_thread(self.init_whitelist)
            self.start_daemon_thread(self.popup_intercept_thread)

            def log_callback(x):
                self.write_log("INFO", "Load Engine", source=os.path.basename(x))

            self.heuristic.load_path(self.path_heuristic, callback=log_callback)
            self.properties.load_path(self.path_properties, callback=log_callback)
            self.write_log("INFO", "System", detail="Engine Initialization Complete")

            if "-scan" in self.args_pyas:
                try:
                    idx = self.args_pyas.index("-scan")
                    self.trigger_context_scan(self.args_pyas[idx+1])
                except Exception:
                    pass

            with self.lock_config:
                first_launch = self.pyas_config.get("first_launch", True)
                driver_enabled = self.pyas_config.get("driver_switch", False)
                context_enabled = self.pyas_config.get("context_switch", True)
                autostart_enabled = self.pyas_config.get("autostart_switch", True)

            self.register_context_menu(context_enabled)
            self.manage_autostart(autostart_enabled)

            if not first_launch:
                with self.lock_config:
                    if self.pyas_config.get("process_switch"):
                        self.start_daemon_thread(self.protect_proc_thread)
                    if self.pyas_config.get("document_switch"):
                        self.start_daemon_thread(self.protect_file_thread)
                    if self.pyas_config.get("system_switch"):
                        self.start_daemon_thread(self.protect_system_thread)
                    if self.pyas_config.get("network_switch"):
                        self.start_daemon_thread(self.protect_net_thread)

                if driver_enabled:
                    if self.install_system_driver():
                        self.start_driver_listener()
                    else:
                        with self.lock_config:
                            self.pyas_config["driver_switch"] = False
                            self.save_config()

                        self.write_log("WARN", "System", detail="Driver Protection Failed to Start", success=False)

        except Exception as e:
            self.write_log("WARN", "init_engine_thread", detail=str(e), success=False)

####################################################################################################

    def yield_files(self, targets):
        if isinstance(targets, str):
            if os.path.isdir(targets):
                for root, dirs, files in os.walk(targets):
                    dirs[:] = [d for d in dirs if not self._is_reparse_point(os.path.join(root, d))]
                    for f in files:
                        yield self.norm_path(os.path.join(root, f)), False

            elif os.path.isfile(targets):
                yield self.norm_path(targets), True

        elif isinstance(targets, (list, tuple, set)):
            for t in targets:
                yield from self.yield_files(t)

    def _is_reparse_point(self, path):
        try:
            if os.path.islink(path):
                return True
            if hasattr(os.path, 'isjunction') and os.path.isjunction(path):
                return True

            st = os.lstat(path)
            return bool(getattr(st, 'st_file_attributes', 0) & 0x400)
        except OSError:
            return False

####################################################################################################

    def scan_engine(self, file_path):
        with self.lock_config:
            ext_switch = self.pyas_config.get("extension_switch", False)
            sen_switch = self.pyas_config.get("sensitive_switch", False)

        try:
            pe_label, _ = self.properties.pe_scan(file_path, enhanced_mode=sen_switch)
            if pe_label:
                return pe_label
        except Exception:
            pass

        try:
            if ext_switch:
                yara_label, _ = self.heuristic.yara_scan(file_path)
                if yara_label:
                    return yara_label
        except Exception:
            pass

        return False

    def safe_scan_engine(self, file_path):
        norm_path = self.norm_path(file_path)
        if not norm_path:
            return False

        file_hash = self.calc_file_hash(norm_path)
        cache_key = file_hash if file_hash else os.path.normcase(norm_path)

        with self.lock_file_ops:
            if cache_key in self.hash_cache:
                return self.hash_cache[cache_key]

            if cache_key in self.scan_events:
                event = self.scan_events[cache_key]
                needs_scan = False
            else:
                event = threading.Event()
                self.scan_events[cache_key] = event
                needs_scan = True

        if not needs_scan:
            event.wait(timeout=60)
            with self.lock_file_ops:
                return self.hash_cache.get(cache_key, False)

        try:
            result = self.scan_engine(norm_path)
            with self.lock_file_ops:
                if len(self.hash_cache) > 10000:
                    for k in list(self.hash_cache.keys())[:1000]:
                        del self.hash_cache[k]

                self.hash_cache[cache_key] = result
            return result

        finally:
            with self.lock_file_ops:
                if cache_key in self.scan_events:
                    self.scan_events[cache_key].set()
                    del self.scan_events[cache_key]

            gc.collect()

####################################################################################################

    def start_scan(self, targets):
        with self.lock_virus:
            if getattr(self, 'scan_running', False):
                return

            self.scan_running = True
            self.scan_finished = False
            self.virus_results = []
            self.scan_count = 0
            self.scan_start = time.time()

        self.scan_pool.submit(self.scan_worker, targets)

    def scan_worker(self, targets):
        last_update = 0.0
        try:
            for file_path, is_explicit in self.yield_files(targets):
                with self.lock_virus:
                    if not self.scan_running:
                        break

                norm_path = self.norm_path(file_path)
                if not norm_path:
                    continue

                current_time = time.time()
                if current_time - last_update >= 0.05:
                    if self._window:
                        js_cmd = f"if(window.updateScanProgress) window.updateScanProgress({json.dumps(norm_path.replace(os.sep, '/'))});"
                        self.ui_queue.put(js_cmd)

                    last_update = current_time

                was_locked = False
                try:
                    with self.lock_file_ops:
                        if norm_path in self.virus_lock:
                            self.lock_file(norm_path, False)
                            was_locked = True

                    if self.is_in_whitelist(norm_path):
                        continue

                    with self.lock_virus:
                        self.scan_count += 1

                    with self.lock_config:
                        ext_filter = self.pyas_config.get("suffix_switch", True)
                        suffix = self.pyas_config.get("suffix", [])

                    if not is_explicit and ext_filter and os.path.splitext(norm_path)[-1].lower() not in suffix:
                        continue

                    result = self.safe_scan_engine(norm_path)
                    if result:
                        with self.lock_virus:
                            self.virus_results.append(norm_path)

                        if self._window: 
                            js_cmd = f"if(window.addVirusResult) window.addVirusResult({json.dumps(result)}, {json.dumps(norm_path.replace(os.sep, '/'))});"
                            self.ui_queue.put(js_cmd)

                        self.write_log("SCAN", "Virus Detected", source=norm_path, file_hash=self.calc_file_hash(norm_path))

                    self.cloud_check(norm_path)
                except Exception as e:
                    self.write_log("WARN", "Scan Engine", source=norm_path, detail=str(e), success=False)

                finally:
                    if was_locked:
                        self.lock_file(norm_path, True)

        finally:
            with self.lock_virus:
                self.scan_running = False
                self.scan_finished = True
                count, scanned, elapsed = len(self.virus_results), self.scan_count, int(time.time() - self.scan_start)

            messages = {
                "traditional_switch": f"發現 {count} 個病毒，掃描 {scanned} 個檔案，耗時 {elapsed} 秒",
                "simplified_switch": f"发现 {count} 个病毒，扫描 {scanned} 个文件，耗时 {elapsed} 秒",
                "english_switch": f"Found {count} viruses, scanned {scanned} files, time {elapsed}s",
                "japanese_switch": f"{count} 個のウイルスを発見し、{scanned} 個のファイルをスキャンしました（所要時間 {elapsed} 秒）",
                "korean_switch": f"바이러스 {count}개 발견, 파일 {scanned}개 검사, 소요 시간 {elapsed}초",
                "french_switch": f"{count} virus trouvés, {scanned} fichiers analysés, temps {elapsed}s",
                "spanish_switch": f"Se encontraron {count} virus, {scanned} archivos escaneados, tiempo {elapsed}s",
                "hindi_switch": f"{count} वायरस मिले, {scanned} फ़ाइलें स्कैन की गईं, समय {elapsed}s",
                "arabic_switch": f"تم العثور على {count} فيروسات، تم فحص {scanned} ملفات، الوقت {elapsed} ثانية",
                "russian_switch": f"Найдено {count} вирусов, проверено {scanned} файлов, время {elapsed}с",
                "slovenian_switch": f"Najdenih {count} virusov, skeniranih {scanned} datotek, čas {elapsed}s"
            }
            if self._window:
                js_cmd = f"if(window.finishScan) window.finishScan({json.dumps(messages)}, {count});"
                self.ui_queue.put(js_cmd)

            self.write_log("INFO", "Scan Completed", detail=f"Found {count} viruses, scanned {scanned} files, time {elapsed}s")

####################################################################################################

    def stop_scan(self):
        with self.lock_virus: self.scan_running = False

    def trigger_scan(self, method):
        messages = {
            "traditional_switch": "已取消掃描",
            "simplified_switch": "已取消扫描", "english_switch":
            "Scan cancelled", "japanese_switch": "スキャンがキャンセルされました",
            "korean_switch": "스캔이 취소되었습니다",
            "french_switch": "Analyse annulée",
            "spanish_switch": "Escaneo cancelado",
            "hindi_switch": "स्कैन रद्द कर दिया गया",
            "arabic_switch": "تم إلغاء الفحص",
            "russian_switch": "Сканирование отменено",
            "slovenian_switch": "Skeniranje preklicano"
        }
        targets = []

        if method == "smart":
            for folder in ["Desktop", "Downloads", "AppData"]:
                fp = os.path.join(self.path_user, folder)
                if os.path.exists(fp):
                    targets.append(fp)

            if os.path.exists(self.path_config):
                targets.append(self.path_config)

            buf = ctypes.create_unicode_buffer(1024)
            max_address = 0x7FFFFFFFFFFF if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x7FFFFFFF
            system_dir = self.path_system.lower()

            for proc in self.get_process_list():
                if proc["path"] and proc["path"] != "None": 
                    targets.append(proc["path"])

                pid = proc["pid"]
                if pid <= 4:
                    continue

                h_process = self.kernel32.OpenProcess(0x1000, False, pid)
                if h_process:
                    try:
                        address = 0
                        mbi = MEMORY_BASIC_INFORMATION()
                        while address < max_address and self.kernel32.VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                            if mbi.State == 0x1000 and mbi.Type == 0x1000000:
                                if self.psapi.GetMappedFileNameW(h_process, ctypes.c_void_p(address), buf, 1024):
                                    raw_path = buf.value
                                    if raw_path.startswith("\\"):
                                        raw_path = self.device_path_to_drive(raw_path)

                                    file_path = self.norm_path(raw_path)
                                    if file_path and not file_path.lower().startswith(system_dir):
                                        targets.append(file_path)

                            if mbi.RegionSize == 0:
                                break
                            address += mbi.RegionSize
                    finally:
                        self.kernel32.CloseHandle(h_process)

            self.start_scan(list(set(targets)))

        elif method == "file":
            targets = self.select_files()
            if targets:
                self.start_scan(targets)

            elif self._window:
                self._window.evaluate_js(f"if(window.finishScan) window.finishScan({json.dumps(messages)}, 0);")

        elif method == "path":
            targets = self.select_folder()
            if targets:
                self.start_scan(targets)

            elif self._window:
                self._window.evaluate_js(f"if(window.finishScan) window.finishScan({json.dumps(messages)}, 0);")

        elif method == "full":
            targets = [f"{chr(d)}:/" for d in range(65, 91) if os.path.exists(f"{chr(d)}:/")]
            self.start_scan(targets)

####################################################################################################

    def solve_scan(self, file_paths):
        deleted_paths = []
        proc_map = {}
        for proc in self.get_process_list():
            if proc["path"] and proc["path"] != "None":

                norm_p = self.norm_path(proc["path"], must_exist=False)
                if norm_p:
                    proc_map.setdefault(os.path.normcase(norm_p), []).append(proc["pid"])

        last_update = 0.0
        with self.lock_virus:
            deleted_set = set()
            for raw_path in file_paths:

                path = self.norm_path(raw_path, must_exist=False)
                if not path:
                    continue

                current_time = time.time()
                if current_time - last_update >= 0.05:
                    if self._window:
                        self._window.evaluate_js(f"if(window.updateDeleteProgress) window.updateDeleteProgress({json.dumps(path.replace(os.sep, '/'))});")

                    last_update = current_time

                try:
                    if path in self.virus_lock:
                        self.lock_file(path, False)

                    path_key = os.path.normcase(path)
                    if path_key in proc_map:
                        for pid in proc_map[path_key]:
                            self.kill_process(pid)

                    try:
                        os.chmod(path, stat.S_IWRITE)
                    except Exception:
                        pass

                    delete_success = False
                    for _ in range(5):
                        try:
                            os.remove(path)
                            delete_success = True
                            break

                        except Exception:
                            time.sleep(0.1)

                    if not delete_success:
                        os.remove(path)

                    self.remove_list_items("quarantine", [path])
                    deleted_paths.append(raw_path) 
                    deleted_set.add(path)
                    self.write_log("INFO", "Virus Delete", source=path, file_hash=self.calc_file_hash(path), operate=True, success=True)

                except Exception as e:
                    self.lock_file(path, True)
                    self.write_log("SCAN", "Virus Delete", source=path, file_hash=self.calc_file_hash(path), detail=str(e), operate=True, success=False)

            if deleted_set:
                self.virus_results = [p for p in self.virus_results if p not in deleted_set]

            remaining = len(self.virus_results)

        messages = {
            "traditional_switch": f"剩餘 {remaining} 個病毒，已刪除 {len(deleted_paths)} 個檔案。",
            "simplified_switch": f"剩余 {remaining} 个病毒，已删除 {len(deleted_paths)} 个文件。",
            "english_switch": f"Remaining {remaining} viruses, deleted {len(deleted_paths)} files.",
            "japanese_switch": f"残りのウイルス {remaining} 個、削除されたファイル {len(deleted_paths)} 個。",
            "korean_switch": f"남은 바이러스 {remaining}개, 삭제된 파일 {len(deleted_paths)}개.",
            "french_switch": f"Virus restants : {remaining}, fichiers supprimés : {len(deleted_paths)}.",
            "spanish_switch": f"Virus restantes: {remaining}, archivos eliminados: {len(deleted_paths)}.",
            "hindi_switch": f"शेष वायरस {remaining}, हटाए गए फ़ाइलें {len(deleted_paths)}.",
            "arabic_switch": f"الفيروسات المتبقية {remaining}، تم حذف {len(deleted_paths)} ملفات.",
            "russian_switch": f"Осталось вирусов: {remaining}, удалено файлов: {len(deleted_paths)}.",
            "slovenian_switch": f"Preostalih virusov: {remaining}, izbrisanih datotek: {len(deleted_paths)}."
        }
        if self._window:
            self._window.evaluate_js(f"if(window.finishScan) window.finishScan({json.dumps(messages)}, {remaining});")

        return deleted_paths

    def remove_virus_result(self, paths):
        with self.lock_virus:
            norm_paths = set(self.norm_path(p, must_exist=False) for p in paths)
            self.virus_results = [p for p in self.virus_results if p not in norm_paths]
            return len(self.virus_results)

####################################################################################################

    def cloud_check(self, file_path):
        norm_path = self.norm_path(file_path)
        if not norm_path:
            return

        cache_key = os.path.normcase(norm_path)
        with self.lock_file_ops:
            if cache_key in self.cloud_pending:
                return

            self.cloud_pending.add(cache_key)

        self.cloud_queue.put(norm_path)

    def cloud_worker(self):
        while True:
            try:
                file_path = self.cloud_queue.get()
                cache_key = os.path.normcase(file_path)

                try:
                    self.perform_cloud_scan(file_path)
                finally:
                    with self.lock_file_ops:
                        self.cloud_pending.discard(cache_key)

                    self.cloud_queue.task_done()
            except Exception:
                pass

    def perform_cloud_scan(self, file_path):
        was_locked = False
        try:
            with self.lock_config:
                if not self.pyas_config.get("cloud_switch", True):
                    return False

                api_host, api_key, max_size = self.pyas_config.get("api_host"), self.pyas_config.get("api_key"), self.pyas_config.get("size", 256 * 1024 * 1024)

            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                return False

            with self.lock_file_ops:
                if file_path in self.virus_lock:
                    self.lock_file(file_path, False)
                    was_locked = True

            if os.path.getsize(file_path) > max_size:
                if was_locked:
                    self.lock_file(file_path, True)
                return False

            file_hash = self.calc_file_hash(file_path)
            success, sha256 = self.cloud.upload_file(file_path, api_host, api_key, file_hash=file_hash)
            if was_locked:
                self.lock_file(file_path, True)
                was_locked = False

            if not success:
                self.write_log("WARN", "Cloud API", source=file_path, detail="Failed", success=False)

        except Exception as e:
            self.write_log("WARN", "perform_cloud_scan", detail=str(e), success=False)

        finally:
            if was_locked:
                try:
                    self.lock_file(file_path, True)
                except Exception:
                    pass
        return False
