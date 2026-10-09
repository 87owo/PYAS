from PYAS_Diagnostics import log_exception
import os
import time
import shutil


class ThreatMixin:
    def manage_named_list(self, list_key, files, action="add", lock_func=None):
        if list_key == "quarantine" and lock_func is None:
            lock_func = self.lock_file

        norm_paths = self.norm_path(files or [], must_exist=False)

        if isinstance(norm_paths, str):
            norm_paths = [norm_paths] if norm_paths else []

        if not norm_paths:
            return 0

        if list_key == "custom_rule":
            acted_items = []
            os.makedirs(self.path_rules, exist_ok=True)

            for file_path in norm_paths:
                if action == "add":
                    if os.path.exists(file_path) and file_path.lower().endswith(".json"):
                        dest = os.path.join(self.path_rules, os.path.basename(file_path))

                        if file_path != dest:
                            try:
                                shutil.copy2(file_path, dest)
                                acted_items.append(dest)

                            except Exception:
                                log_exception("PYAS_Threats.ThreatMixin.manage_named_list:34")
                                pass
                        else:
                            acted_items.append(dest)

                elif action == "remove":
                    try:
                        if os.path.exists(file_path):
                            os.remove(file_path)

                        acted_items.append(file_path)
                    except Exception:
                        log_exception("PYAS_Threats.ThreatMixin.manage_named_list:45")
                        pass

            if acted_items and getattr(self, "driver_port", None):
                self.clear_driver_rules()

                for f in os.listdir(self.path_rules):
                    if f.lower().endswith(".json"):
                        self.load_driver_rule_file(os.path.join(self.path_rules, f))

            return len(acted_items)

        if action == "add":
            if list_key == "white_list":
                self.remove_list_items("quarantine", norm_paths)

            elif list_key == "quarantine":
                self.remove_list_items("white_list", norm_paths)

        acted_items = []

        with self.lock_config:
            target_list = self.pyas_config.setdefault(list_key, [])

            if action == "add":
                for path in norm_paths:
                    path_case = os.path.normcase(path)
                    exists = False

                    for item in target_list:
                        val = item.get("file", "") if isinstance(item, dict) else item
                        np = self.norm_path(val, must_exist=False)

                        if np and os.path.normcase(np) == path_case:
                            exists = True
                            break

                    if not exists:
                        if lock_func:
                            lock_func(path, True)

                        new_item = {"file": path, "time": time.time()}
                        is_directory = None

                        if list_key == "white_list":
                            is_directory = os.path.isdir(path)
                            new_item["is_dir"] = is_directory

                        target_list.append(new_item)
                        acted_items.append(path)

                        if list_key == "white_list":
                            self.sync_driver_whitelist(path, True, is_directory)

            elif action == "remove":
                norm_paths_case = {os.path.normcase(p) for p in norm_paths}
                new_list = []

                for item in target_list:
                    val = item.get("file", "") if isinstance(item, dict) else item

                    if val:
                        np = self.norm_path(val, must_exist=False)

                        if np and os.path.normcase(np) in norm_paths_case:
                            if lock_func:
                                lock_func(val, False)

                            acted_items.append(val)

                            if list_key == "white_list":
                                is_directory = (
                                    item.get("is_dir") if isinstance(item, dict) else None
                                )
                                self.sync_driver_whitelist(val, False, is_directory)

                            continue

                    new_list.append(item)

                target_list[:] = new_list

            if acted_items:
                self.write_log(
                    "INFO", "Config Update", detail=f"List [{list_key}] {action}: {acted_items}"
                )
                self.save_config()

        return len(acted_items)

    def remove_list_items(self, list_key, paths_to_remove):
        if list_key == "custom_rule":
            return self.manage_named_list(list_key, paths_to_remove, action="remove") > 0

        with self.lock_config:
            target_list = self.pyas_config.get(list_key, [])
            original_len = len(target_list)

            norm_paths_to_remove = set()

            for p in paths_to_remove:
                np = self.norm_path(p, must_exist=False)

                if np:
                    norm_paths_to_remove.add(os.path.normcase(np))

            if list_key == "quarantine":
                for item in target_list:
                    val = item.get("file") if isinstance(item, dict) else item

                    if val:
                        np = self.norm_path(val, must_exist=False)

                        if np and os.path.normcase(np) in norm_paths_to_remove:
                            self.lock_file(val, False)

            new_list = []
            removed_items = []

            for item in target_list:
                val = (
                    item.get("file") or item.get("exe") or item.get("title")
                    if isinstance(item, dict)
                    else item
                )

                if val:
                    np = self.norm_path(val, must_exist=False)

                    if np and os.path.normcase(np) in norm_paths_to_remove:
                        removed_items.append(val)

                        if list_key == "white_list":
                            is_directory = item.get("is_dir") if isinstance(item, dict) else None
                            self.sync_driver_whitelist(val, False, is_directory)

                        continue

                new_list.append(item)

            self.pyas_config[list_key] = new_list

            if len(self.pyas_config[list_key]) < original_len:
                self.write_log(
                    "INFO", "Config Update", detail=f"List [{list_key}] remove: {removed_items}"
                )
                self.save_config()
                return True

        return False

    def extract_list_items(self, paths, dest_dir):
        if not dest_dir or not os.path.exists(dest_dir):
            return False

        extracted_count = 0

        for raw_path in paths:
            src = self.norm_path(raw_path, must_exist=True)

            if not src:
                continue

            base_name = os.path.basename(src)
            target_path = os.path.join(dest_dir, base_name)

            if os.path.exists(target_path):
                name, ext = os.path.splitext(base_name)
                counter = 1

                while os.path.exists(target_path):
                    target_path = os.path.join(dest_dir, f"{name} ({counter}){ext}")
                    counter += 1

            was_locked = False
            src_norm = os.path.normcase(src)
            src_dir = src_norm + os.sep

            with self.lock_file_ops:
                for locked_path in self.virus_lock:
                    locked_norm = os.path.normcase(locked_path)

                    if locked_norm == src_norm or locked_norm.startswith(src_dir):
                        was_locked = True
                        break

                if was_locked:
                    self.lock_file(src, False)

            try:
                if os.path.isdir(src):
                    shutil.copytree(src, target_path)
                else:
                    shutil.copy2(src, target_path)

                extracted_count += 1
                self.write_log("INFO", "File Extract", source=src, target=target_path, operate=True)

            except Exception as e:
                log_exception("PYAS_Threats.ThreatMixin.extract_list_items:210")
                self.write_log(
                    "WARN", "extract_list_items", source=src, detail=str(e), success=False
                )
            finally:
                if was_locked:
                    self.lock_file(src, True)

        return extracted_count > 0
