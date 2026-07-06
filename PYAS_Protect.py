import os, time, shutil, msvcrt, winreg, threading, subprocess
import ctypes, ctypes.wintypes

from PYAS_Tools import FILE_NOTIFY_INFORMATION, LUID, MEMORY_BASIC_INFORMATION, POINT, PYAS_FULL_MESSAGE, PYAS_USER_MESSAGE, RECT, SERVICE_STATUS_PROCESS, TOKEN_PRIVILEGES

FLT_PORT_FLAG_SYNC_HANDLE = 0x00000001
HRESULT_IO_PENDING = 0x800703E5
ERROR_OPERATION_ABORTED = 995
ERROR_NOT_FOUND = 1168
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258

class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", ctypes.wintypes.DWORD),
        ("OffsetHigh", ctypes.wintypes.DWORD),
        ("hEvent", ctypes.wintypes.HANDLE)
    ]

####################################################################################################

class ProtectMixin:
    def is_in_whitelist(self, file_path):
        p = self.norm_path(file_path, must_exist=False)
        if not p: 
            return False

        p_norm = os.path.normcase(p)

        with self.lock_config: 
            whitelist = self.pyas_config.get("white_list", [])

        for item in whitelist:
            if isinstance(item, dict):
                wl_path = item.get("file", "")
                wl_norm = self.norm_path(wl_path, must_exist=False)
                if not wl_norm:
                    continue

                wl_norm = os.path.normcase(wl_norm)

                if p_norm == wl_norm:
                    return True

                if not wl_norm.endswith(os.sep):
                    wl_norm += os.sep

                if p_norm.startswith(wl_norm):
                    return True

        return False

    def init_whitelist(self):
        self.manage_named_list("white_list", [self.file_pyas], action="add")

    def sync_driver_whitelist(self, file_path, is_add=True):
        with self.lock_driver:
            if not self.driver_port:
                return False

            driver_path = str(file_path)
            drive_letter = os.path.splitdrive(driver_path)[0]
            if drive_letter:
                driver_path = "*" + driver_path[len(drive_letter):]

            msg = PYAS_USER_MESSAGE()
            msg.Command = 1 if is_add else 2
            msg.Path = driver_path
            bytes_returned = ctypes.wintypes.DWORD(0)

            try:
                return self.fltlib.FilterSendMessage(self.driver_port, ctypes.byref(msg), ctypes.sizeof(msg), None, 0, ctypes.byref(bytes_returned)) == 0
            except Exception:
                return False

####################################################################################################

    def lock_file(self, target_path, lock, quiet=False):
        with self.lock_file_ops:
            if lock:
                if not os.path.exists(target_path):
                    return

                paths_to_lock = []
                if os.path.isdir(target_path):
                    for root, _, files in os.walk(target_path):
                        for f in files:
                            paths_to_lock.append(os.path.join(root, f))
                else:
                    paths_to_lock.append(target_path)

                for file_path in paths_to_lock:
                    if file_path in self.virus_lock:
                        continue

                    success = False
                    last_error = None
                    for _ in range(5):
                        try:
                            fd = os.open(file_path, os.O_RDWR | os.O_BINARY)
                            try:
                                try:
                                    size = os.path.getsize(file_path)
                                except Exception:
                                    size = 1

                                lock_size = size if size > 0 else 1
                                msvcrt.locking(fd, msvcrt.LK_NBRLCK, lock_size)
                                self.virus_lock[file_path] = (fd, lock_size)
                                success = True
                                break

                            except Exception as e:
                                os.close(fd)
                                raise e

                        except Exception as e:
                            last_error = e
                            time.sleep(0.1)

                    if not success and not quiet:
                        self.write_log("WARN", "lock_file", source=file_path, detail=str(last_error), success=False)
            else:
                target_norm = os.path.normcase(target_path)
                target_dir = target_norm + os.sep
                keys_to_unlock = []

                for locked_path in self.virus_lock:
                    locked_norm = os.path.normcase(locked_path)
                    if locked_norm == target_norm or locked_norm.startswith(target_dir):
                        keys_to_unlock.append(locked_path)

                for file_path in keys_to_unlock:
                    fd, lock_size = self.virus_lock[file_path]
                    try:
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, lock_size)
                    except Exception as e:
                        if not quiet:
                            self.write_log("WARN", "unlock_file", source=file_path, detail=str(e), success=False)

                    finally:
                        try:
                            os.close(fd)
                        except Exception:
                            pass
                        del self.virus_lock[file_path]

    def relock_file(self):
        while True:
            try:
                with self.lock_config:
                    quarantine_list = self.pyas_config.get("quarantine", [])

                with self.lock_file_ops:
                    locked_keys = set(self.virus_lock.keys())

                for item in quarantine_list:
                    file_path = item.get("file")
                    if not file_path or not os.path.exists(file_path):
                        continue

                    if os.path.isdir(file_path):
                        self.lock_file(file_path, True, quiet=True)
                    elif file_path not in locked_keys:
                        self.lock_file(file_path, True, quiet=True)

            except Exception:
                pass
            time.sleep(5)

####################################################################################################

    def backup_mbr(self, max_drives=26):
        self.mbr_backup = {}
        for drive in range(max_drives):
            try:
                with open(rf"\\.\PhysicalDrive{drive}", "rb") as f:
                    mbr = f.read(512)
                    if len(mbr) == 512 and mbr[510:512] == b"\x55\xAA":
                        self.mbr_backup[drive] = mbr

            except Exception:
                continue

    def check_system_mbr(self):
        for drive, mbr_value in list(self.mbr_backup.items()):
            try:
                with open(rf"\\.\PhysicalDrive{drive}", "rb") as f:
                    if f.read(512) != mbr_value:
                        return True

            except Exception:
                pass
        return False

    def repair_system_mbr(self):
        for drive, mbr_value in list(self.mbr_backup.items()):
            drive_path = rf"\\.\PhysicalDrive{drive}"
            try:
                with open(drive_path, "rb+") as f:
                    if f.read(512) != mbr_value:
                        f.seek(0); f.write(mbr_value)
                        self.write_log("INFO", "MBR Repaired", source=drive_path, operate=True)

            except Exception:
                pass

####################################################################################################

    def _get_restrict_lists(self):
        permissions = [
            "NoControlPanel", "NoDrives", "NoFileMenu", "NoFind", "NoStartMenuPinnedList", "NoSetFolders", "NoSetFolderOptions", "NoViewOnDrive", "NoClose", "NoDesktop",
            "NoLogoff", "NoFolderOptions", "RestrictRun", "NoViewContextMenu", "HideClock", "NoStartMenuMyGames", "NoStartMenuMyMusic", "DisableCMD", "NoAddingComponents",
            "NoWinKeys", "NoStartMenuLogOff", "NoSimpleNetIDList", "NoLowDiskSpaceChecks", "DisableLockWorkstation","Restrict_Run", "DisableTaskMgr", "DisableRegistryTools",
            "DisableChangePassword", "Wallpaper", "NoComponents", "NoStartMenuMorePrograms", "NoActiveDesktop", "NoSetActiveDesktop", "NoRecentDocsMenu", "NoWindowsUpdate",
            "NoChangeStartMenu", "NoFavoritesMenu", "NoRecentDocsHistory", "NoSetTaskbar", "NoSMHelp", "NoTrayContextMenu", "NoManageMyComputerVerb", "NoRealMode", "NoRun",
            "ClearRecentDocsOnExit", "NoActiveDesktopChanges", "NoStartMenuNetworkPlaces"
        ]
        paths = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\MMC"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\Windows\System"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System")
        ]
        return permissions, paths

    def check_system_restrict(self):
        permissions, paths = self._get_restrict_lists()
        for hkey, path in paths:
            for val in permissions:
                if self._reg_read(hkey, path, val) is not None:
                    return True

        return False

    def check_system_file_type(self):
        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for ext in [".exe", ".bat", ".cmd", ".com"]:
                if self._reg_read(root, rf"SOFTWARE\Classes\{ext}", "") != ("exefile" if ext == ".exe" else ext[1:]+"file"):
                    return True

            for cmd in ["open", "runas"]:
                if self._reg_read(root, rf"SOFTWARE\Classes\exefile\shell\{cmd}\command", "") != '"%1" %*':
                    return True

        return False

    def check_system_file_icon(self):
        return any(self._reg_read(root, r"SOFTWARE\Classes\exefile\DefaultIcon", "") != "%1" for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER])

    def check_system_image(self):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", 0, winreg.KEY_READ) as reg:
                i = 0
                while True:
                    try:
                        subkey = winreg.EnumKey(reg, i)
                        with winreg.OpenKey(reg, subkey, 0, winreg.KEY_READ) as sub_reg:
                            for val in ["Debugger", "UseFilter", "GlobalFlag", "MitigationOptions"]:
                                try:
                                    winreg.QueryValueEx(sub_reg, val);
                                    return True

                                except FileNotFoundError:
                                    pass

                        i += 1
                    except OSError:
                        break

        except Exception:
            pass
        return False

    def check_system_wallpaper(self):
        return self._reg_read(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "Wallpaper") != os.path.join(self.path_system, "web", "wallpaper", "Windows", "img0.jpg")

    def scan_system_repair(self):
        items = []

        for drive, mbr_value in list(self.mbr_backup.items()):
            drive_path = rf"\\.\PhysicalDrive{drive}"
            try:
                with open(drive_path, "rb") as f:
                    if f.read(512) != mbr_value:
                        items.append({"id": f"mbr|{drive}", "display": "repair_mbr", "path": drive_path})

            except Exception:
                pass

        permissions, paths = self._get_restrict_lists()
        for hkey, path in paths:
            for val in permissions:

                if self._reg_read(hkey, path, val) is not None:
                    root = "HKLM" if hkey == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                    items.append({"id": f"restrict|{root}\\{path}\\{val}", "display": "repair_limit", "path": rf"{root}\{path}\{val}"})

        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            root_str = "HKLM" if root == winreg.HKEY_LOCAL_MACHINE else "HKCU"

            for ext in [".exe", ".bat", ".cmd", ".com"]:
                expected = "exefile" if ext == ".exe" else ext[1:] + "file"
                if self._reg_read(root, rf"SOFTWARE\Classes\{ext}", "") != expected:
                    items.append({"id": f"file_type|{root_str}\\{ext}", "display": "repair_assoc", "path": rf"{root_str}\SOFTWARE\Classes\{ext}"})

            for cmd in ["open", "runas"]:
                if self._reg_read(root, rf"SOFTWARE\Classes\exefile\shell\{cmd}\command", "") != '"%1" %*':
                    items.append({"id": f"file_type|{root_str}\\exefile\\{cmd}", "display": "repair_assoc", "path": rf"{root_str}\SOFTWARE\Classes\exefile\shell\{cmd}\command"})

            if self._reg_read(root, r"SOFTWARE\Classes\exefile\DefaultIcon", "") != "%1":
                items.append({"id": f"file_icon|{root_str}", "display": "repair_icon", "path": rf"{root_str}\SOFTWARE\Classes\exefile\DefaultIcon"})

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", 0, winreg.KEY_READ) as reg:
                i = 0
                while True:
                    try:
                        subkey = winreg.EnumKey(reg, i)
                        with winreg.OpenKey(reg, subkey, 0, winreg.KEY_READ) as sub_reg:
                            for val in ["Debugger", "UseFilter", "GlobalFlag", "MitigationOptions"]:
                                try:
                                    winreg.QueryValueEx(sub_reg, val)
                                    items.append({"id": f"image|{subkey}", "display": "repair_hijack", "path": rf"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{subkey}"})
                                    break
                                except FileNotFoundError:
                                    pass

                        i += 1
                    except OSError:
                        break

        except Exception:
            pass

        wp = self._reg_read(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "Wallpaper")
        expected_wp = os.path.join(self.path_system, "web", "wallpaper", "Windows", "img0.jpg")
        if wp != expected_wp:
            items.append({"id": "wallpaper|0", "display": "repair_wallpaper", "path": wp if wp else r"HKCU\Control Panel\Desktop\Wallpaper"})

        return items

    def repair_system_restrict(self):
        permissions, paths = self._get_restrict_lists()
        for hkey, path in paths:
            for val in permissions:
                self._reg_delete(hkey, path, val)

    def repair_system_file_type(self):
        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for ext in [".exe", ".bat", ".cmd", ".com"]:
                self._reg_write(root, rf"SOFTWARE\Classes\{ext}", None, winreg.REG_SZ, "exefile" if ext == ".exe" else ext[1:]+"file")

            for cmd in ["open", "runas"]:
                self._reg_write(root, rf"SOFTWARE\Classes\exefile\shell\{cmd}\command", None, winreg.REG_SZ, '"%1" %*')

    def repair_system_file_icon(self):
        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]: self._reg_write(root, r"SOFTWARE\Classes\exefile\DefaultIcon", None, winreg.REG_SZ, "%1")

    def repair_system_image(self):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", 0, winreg.KEY_ALL_ACCESS) as reg:
                i = 0
                while True:
                    try:
                        subkey = winreg.EnumKey(reg, i)
                        with winreg.OpenKey(reg, subkey, 0, winreg.KEY_ALL_ACCESS) as sub_reg:
                            for val in ["Debugger", "UseFilter", "GlobalFlag", "MitigationOptions"]:
                                try:
                                    winreg.DeleteValue(sub_reg, val)
                                except FileNotFoundError:
                                    pass

                        i += 1
                    except OSError:
                        break

        except Exception as e:
            self.write_log("WARN", "repair_system_image", detail=str(e), success=False)

    def repair_system_wallpaper(self):
        try:
            wallpaper = os.path.join(self.path_system, "web", "wallpaper", "Windows", "img0.jpg")
            if not os.path.exists(wallpaper):
                return

            self._reg_write(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "Wallpaper", winreg.REG_SZ, wallpaper)
            theme_dir = os.path.join(self.path_appdata, "Microsoft", "Windows", "Themes")

            for fname in ["TranscodedWallpaper", "TranscodedWallpaper.tmp"]:
                try:
                    os.remove(os.path.join(theme_dir, fname))
                except Exception:
                    pass

            shutil.rmtree(os.path.join(theme_dir, "CachedFiles"), ignore_errors=True)
            self.user32.SystemParametersInfoW(20, 0, wallpaper, 3)

        except Exception as e:
            self.write_log("WARN", "repair_system_wallpaper", detail=str(e), success=False)

    def execute_system_repair(self, items):
        try:
            types = set(item.split('|')[0] for item in items)

            if "mbr" in types:
                self.repair_system_mbr()
            if "restrict" in types:
                self.repair_system_restrict()
            if "file_type" in types:
                self.repair_system_file_type()
            if "file_icon" in types:
                self.repair_system_file_icon()
            if "image" in types:
                self.repair_system_image()
            if "wallpaper" in types:
                self.repair_system_wallpaper()

            self.write_log("INFO", "System Repair", detail=f"Repaired {len(items)} items", operate=True)
            return True

        except Exception as e:
            self.write_log("WARN", "execute_system_repair", detail=str(e), operate=True, success=False)
            return False

####################################################################################################

    def protect_proc_thread(self):
        with self.lock_proc:
            self.exist_process = self.get_process_list_pids()

        while True:
            with self.lock_config:
                if not self.pyas_config.get("process_switch", False):
                    break
            try:
                time.sleep(0.1)
                cur = self.get_process_list_pids()

                with self.lock_proc:
                    new_pids = cur - self.exist_process
                    self.exist_process = cur

                for pid in new_pids:
                    h = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
                    if h:
                        with self.lock_config:
                            should_suspend = self.pyas_config.get("suspend_switch", True)

                        if should_suspend:
                            self.ntdll.NtSuspendProcess(h)
                            with self.lock_proc:
                                self.suspended_procs.add(h)
                        try:
                            self.proc_pool.submit(self.handle_new_process, pid, h, should_suspend)

                        except Exception:
                            if should_suspend:
                                self.ntdll.NtResumeProcess(h)
                                with self.lock_proc:
                                    self.suspended_procs.discard(h)

                            self.kernel32.CloseHandle(h)
            except Exception as e:
                self.write_log("WARN", "protect_proc_thread", detail=str(e), success=False)

    def handle_new_process(self, pid, h=None, suspended=None):
        if suspended is None:
            with self.lock_config:
                suspended = self.pyas_config.get("suspend_switch", True)

        if not h:
            h = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if not h:
                return

            if suspended:
                self.ntdll.NtSuspendProcess(h)
                with self.lock_proc:
                    if not hasattr(self, 'suspended_procs'):
                        self.suspended_procs = set()

                    self.suspended_procs.add(h)
        try:
            cmdline = self.get_process_cmdline(h)
            process_file = self.get_process_file(h)
            if "-scan" in cmdline and self.path_equal(process_file, self.file_pyas):
                return

            raw_targets = self.extract_paths_from_cmdline(cmdline)
            if process_file:
                raw_targets.append(process_file)

            all_targets = []
            for p in raw_targets:
                np = self.norm_path(self.device_path_to_drive(p))
                if np and np not in all_targets:
                    all_targets.append(np)

            with self.lock_config:
                ext_filter = self.pyas_config.get("suffix_switch", True)
                suffix = self.pyas_config.get("suffix", [])
                load_switch = self.pyas_config.get("load_switch", True)

            scan_targets = []
            for file_path in all_targets:
                if not file_path or not os.path.isfile(file_path):
                    continue
                if ext_filter and os.path.splitext(file_path)[-1].lower() not in suffix:
                    continue
                if self.is_in_whitelist(file_path):
                    continue
                if process_file and process_file.lower().endswith("explorer.exe") and "/select" in cmdline.lower():
                    continue
                scan_targets.append(file_path)

            if not scan_targets:
                return

            virus_found = False
            for file_path in scan_targets:
                result = self.safe_scan_engine(file_path)
                self.cloud_check(file_path)

                if result:
                    self.kernel32.TerminateProcess(h, 0)
                    self.write_log("BLOCK", "Process Block", pid=pid, source=file_path, file_hash=self.calc_file_hash(file_path))
                    virus_found = True
                    break

            if not virus_found and load_switch:
                hidden_virus_path = self.scan_process_memory(pid, h)
                if hidden_virus_path:
                    self.kernel32.TerminateProcess(h, 0)
                    self.write_log("BLOCK", "Process DLL Block", pid=pid, source=hidden_virus_path, file_hash=self.calc_file_hash(hidden_virus_path))

        finally:
            if suspended:
                try:
                    self.ntdll.NtResumeProcess(h)
                except Exception:
                    pass
                with self.lock_proc:
                    self.suspended_procs.discard(h)
            try:
                self.kernel32.CloseHandle(h)
            except Exception:
                pass

####################################################################################################

    def scan_process_memory(self, pid, h_process):
        scanned_paths = set()
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        system_dir = self.path_system.lower()

        buf = ctypes.create_unicode_buffer(1024)
        max_address = 0x7FFFFFFFFFFF if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x7FFFFFFF

        with self.lock_config:
            ext_filter = self.pyas_config.get("suffix_switch", True)
            suffix = self.pyas_config.get("suffix", [])

        try:
            while address < max_address and self.kernel32.VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                if mbi.State == 0x1000 and mbi.Type == 0x1000000:
                    if self.psapi.GetMappedFileNameW(h_process, ctypes.c_void_p(address), buf, 1024):

                        raw_path = buf.value
                        if raw_path.startswith("\\"):
                            raw_path = self.device_path_to_drive(raw_path)

                        file_path = self.norm_path(raw_path)
                        if file_path and file_path not in scanned_paths:

                            scanned_paths.add(file_path)
                            file_path_lower = file_path.lower()

                            if not file_path_lower.startswith(system_dir) and not self.is_in_whitelist(file_path):
                                ext = os.path.splitext(file_path_lower)[-1]

                                if ext != ".exe" and (not ext_filter or ext in suffix):
                                    if self.safe_scan_engine(file_path):
                                        return file_path

                                    self.cloud_check(file_path)

                if mbi.RegionSize == 0:
                    break
                address += mbi.RegionSize

        finally:
            scanned_paths.clear()

        return None

####################################################################################################

    def protect_file_thread(self):
        with self.lock_file_ops:
            if getattr(self, 'h_dir_file', None):
                return

        hDir = self.kernel32.CreateFileW(self.path_user, 0x0001, 0x00000007, None, 3, 0x02000000, None)
        if not hDir or hDir == -1:
            return

        with self.lock_file_ops:
            self.h_dir_file = hDir

        try:
            buffer = ctypes.create_string_buffer(262144)
            temp_prefix = os.path.normcase(self.path_temp)
            if not temp_prefix.endswith(os.sep):
                temp_prefix += os.sep

            while True:
                with self.lock_config:
                    if not self.pyas_config.get("document_switch", False): 
                        break
                try:
                    bytes_returned = ctypes.wintypes.DWORD()
                    res = self.kernel32.ReadDirectoryChangesW(self.h_dir_file, buffer, ctypes.sizeof(buffer), True, 0x0000001F, ctypes.byref(bytes_returned), None, None)
                    if not res or bytes_returned.value == 0:
                        break

                    offset = 0
                    while True:
                        notify = FILE_NOTIFY_INFORMATION.from_buffer(buffer, offset)
                        raw_filename = notify.FileName[:notify.FileNameLength // 2]

                        if raw_filename and notify.Action in [1, 3, 5]:
                            file_path = self.norm_path(os.path.join(self.path_user, raw_filename), must_exist=True)

                            if file_path and not self.is_in_whitelist(file_path):
                                norm_path = os.path.normcase(file_path)

                                if not (norm_path.startswith(temp_prefix) and norm_path[len(temp_prefix):].startswith("_mei")):
                                    with self.lock_config:
                                        ext_filter = self.pyas_config.get("suffix_switch", True)
                                        suffix = self.pyas_config.get("suffix", [])

                                    if not ext_filter or os.path.splitext(file_path)[-1].lower() in suffix:
                                        self.protect_pool.submit(self.handle_new_file, file_path)

                        if notify.NextEntryOffset == 0:
                            break

                        offset += notify.NextEntryOffset

                except Exception:
                    break
        finally:
            with self.lock_file_ops:
                if getattr(self, 'h_dir_file', None):
                    try:
                        self.kernel32.CloseHandle(self.h_dir_file)
                    except Exception:
                        pass
                    self.h_dir_file = None

    def handle_new_file(self, file_path):
        try:
            for _ in range(5):
                try:
                    fd = os.open(file_path, os.O_RDONLY | os.O_BINARY)
                    os.close(fd)

                    size = os.path.getsize(file_path)
                    if size > 0:
                        break

                except Exception:
                    pass
                time.sleep(0.1)
            else:
                return

            with self.lock_file_ops:
                if file_path in self.virus_lock: return

            result = self.safe_scan_engine(file_path)
            self.cloud_check(file_path)

            if result:
                if self.manage_named_list("quarantine", [file_path], action="add", lock_func=self.lock_file) > 0:
                    self.write_log("BLOCK", "File Block", source=file_path, file_hash=self.calc_file_hash(file_path))

        except Exception:
            pass

####################################################################################################

    def protect_net_thread(self):
        with self.lock_net:
            self.exist_connections = set()

        while True:
            with self.lock_config:
                if not self.pyas_config.get("network_switch", False): break

            try:
                time.sleep(0.5)
                conns = self.get_connections_list()

                with self.lock_net:
                    new_conns = conns - self.exist_connections
                    self.exist_connections = conns

                for key in new_conns:
                    self.protect_pool.submit(self.handle_new_connection, key)

            except Exception as e:
                self.write_log("WARN", "protect_net_thread", detail=str(e), success=False)

        with self.lock_net:
            self.exist_connections = set()

    def handle_new_connection(self, key):
        pid, remote_addr, remote_port = key
        try:
            h = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if not h:
                return

            try:
                remote_ip = f"{remote_addr & 0xFF}.{(remote_addr >> 8) & 0xFF}.{(remote_addr >> 16) & 0xFF}.{(remote_addr >> 24) & 0xFF}"
                file_path = self.norm_path(self.get_process_file(h))

                if file_path and not self.is_in_whitelist(file_path) and hasattr(self.heuristic, "network") and remote_ip in self.heuristic.network:
                    self.kernel32.TerminateProcess(h, 0)
                    self.write_log("BLOCK", "Network Block", pid=pid, source=file_path, target=remote_ip, file_hash=self.calc_file_hash(file_path))

            finally:
                self.kernel32.CloseHandle(h)

        except Exception as e:
            self.write_log("WARN", "handle_new_connection", pid=pid, detail=str(e), success=False)

####################################################################################################

    def protect_system_thread(self):
        while True:
            with self.lock_config:
                if not self.pyas_config.get("system_switch", False):
                    break
            try:
                self.repair_system_mbr()
                self.repair_system_restrict()
                self.repair_system_file_type()
                self.repair_system_file_icon()
                self.repair_system_image()
                self.check_process_survival()
                time.sleep(0.5)

            except Exception as e:
                self.write_log("WARN", "protect_system_thread", detail=str(e), success=False)

    def check_process_survival(self):
        try:
            running = any(exe_name.lower() == "explorer.exe" for _, exe_name in self._enum_processes())

            if not running:
                subprocess.Popen("explorer.exe", shell=True)
                self.write_log("INFO", "System Restart", source="explorer.exe")

        except Exception:
            pass

####################################################################################################

    def capture_popup_window(self):
        overlay = self.user32.CreateWindowExW(0x000800A8, "STATIC", "", 0x90000004, 0, 0, 0, 0, None, None, None, None)
        self.user32.SetLayeredWindowAttributes(overlay, 0, 120, 2)

        target_hwnd = None
        last_hwnd = None
        msg = ctypes.wintypes.MSG()

        while self.user32.GetAsyncKeyState(0x01) & 0x8000:
            time.sleep(0.01)

        try:
            start_time = time.time()
            while time.time() - start_time < 30:
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
                        self.user32.SetWindowPos(overlay, -1, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, 0x0050)

                    if self.user32.GetAsyncKeyState(0x01) & 0x8000:
                        target_hwnd = root_hwnd
                        break

                while self.user32.PeekMessageW(ctypes.byref(msg), 0, 0, 0, 1):
                    self.user32.TranslateMessage(ctypes.byref(msg))
                    self.user32.DispatchMessageW(ctypes.byref(msg))

                time.sleep(0.02)
        finally:
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

            if proc_name and not any(item.get("exe") == proc_name or item.get("class") == c_str for item in self.pass_windows):
                return {"exe": proc_name, "class": c_str, "title": t_str}

        return None

    def add_popup_rule(self, rule):
        if not rule:
            return False

        with self.lock_config:
            target_list = self.pyas_config.setdefault("block_list", [])
            if any(item.get("exe") == rule.get("exe") and item.get("class") == rule.get("class") and item.get("title") == rule.get("title") for item in target_list):
                return False

            target_list.append(rule)
            self.write_log("INFO", "Config Update", detail=f"List [block_list] add: {rule}")
            self.save_config()
            return True

    def popup_intercept_thread(self):
        hwnd_list = []

        def enum_windows_callback(hWnd, lParam):
            if self.user32.IsWindowVisible(hWnd):
                hwnd_list.append(hWnd)
            return True

        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
        self._enum_cb_keepalive = WNDENUMPROC(enum_windows_callback)

        while True:
            try:
                time.sleep(0.5)
                with self.lock_config:
                    rules = self.pyas_config.get("block_list", [])
                if not rules:
                    continue

                hwnd_list.clear()
                self.user32.EnumWindows(self._enum_cb_keepalive, 0)

                for hWnd in list(hwnd_list):
                    pid = ctypes.c_ulong(0)
                    self.user32.GetWindowThreadProcessId(hWnd, ctypes.byref(pid))
                    if pid.value <= 4:
                        continue

                    proc_name, _ = self.get_exe_info(pid.value)
                    length = self.user32.GetWindowTextLengthW(hWnd)
                    title, class_name = ctypes.create_unicode_buffer(length + 1), ctypes.create_unicode_buffer(256)

                    self.user32.GetWindowTextW(hWnd, title, length + 1)
                    self.user32.GetClassNameW(hWnd, class_name, 256)
                    t_str, c_str = str(title.value), str(class_name.value)

                    if any(item.get("exe") == proc_name or item.get("class") == c_str for item in self.pass_windows):
                        continue

                    is_block = False
                    for item in rules:
                        if item.get("exe") and item.get("exe") == proc_name and (item.get("class") == c_str or item.get("title") == t_str):
                            is_block = True
                            break

                    if is_block:
                        for msg in [0x0010, 0x0002, 0x0012, 0x0112]:
                            self.user32.SendMessageW(hWnd, msg, 0xF060, 0)
                        if proc_name:
                            self.kill_process(pid.value)

            except Exception:
                pass

####################################################################################################

    def _query_service_state_handle(self, service):
        status = SERVICE_STATUS_PROCESS()
        needed = ctypes.wintypes.DWORD(0)
        buffer = ctypes.cast(ctypes.byref(status), ctypes.POINTER(ctypes.c_ubyte))

        if not self.advapi32.QueryServiceStatusEx(service, 0, buffer, ctypes.sizeof(status), ctypes.byref(needed)):
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
                    scm, "PYAS_Driver", "PYAS_Driver", desired_service_access,
                    0x00000001, 0x00000003, 0x00000001, self.path_drivers,
                    "FSFilter Activity Monitor", None, dependencies_ptr, None, None
                )

                if not service:
                    last_error = ctypes.get_last_error()
                    if last_error in (1073, 1078):
                        service = self.advapi32.OpenServiceW(scm, "PYAS_Driver", desired_service_access)
                        if not service:
                            last_error = ctypes.get_last_error()

                    elif last_error == 1072:
                        pass

                if service:
                    ctypes.set_last_error(0)
                    changed = self.advapi32.ChangeServiceConfigW(
                        service, 0x00000001, 0x00000003, 0x00000001, self.path_drivers,
                        "FSFilter Activity Monitor", None, dependencies_ptr, None, None, None
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

    def _delete_driver_service(self):
        scm = self.advapi32.OpenSCManagerW(None, None, 0x0001)
        if not scm:
            return False, ctypes.get_last_error()

        service = None
        try:
            service = self.advapi32.OpenServiceW(scm, "PYAS_Driver", 0x0004 | 0x00010000)
            if not service:
                error = ctypes.get_last_error()
                return (True, 0) if error in (1060, 1072) else (False, error)

            state, error = self._query_service_state_handle(service)
            if error:
                return False, error
            if state in (2, 3, 4):
                return False, 1051

            ctypes.set_last_error(0)
            if self.advapi32.DeleteService(service):
                return True, 0

            error = ctypes.get_last_error()
            if error in (1060, 1072):
                return True, 0
            return False, error
        finally:
            if service:
                self.advapi32.CloseServiceHandle(service)
            self.advapi32.CloseServiceHandle(scm)

    def install_system_driver(self):
        try:
            ensured, service_error = self._ensure_driver_service()
            if not ensured:
                self.write_log("WARN", "Driver Service", detail=f"CreateServiceW/ChangeServiceConfigW failed: 0x{service_error & 0xFFFFFFFF:08X}", success=False)
                return False

            self._reg_write(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\PYAS_Driver\Instances", "DefaultInstance", winreg.REG_SZ, "PYAS Instance")
            self._reg_write(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\PYAS_Driver\Instances\PYAS Instance", "Altitude", winreg.REG_SZ, "320000")
            self._reg_write(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\PYAS_Driver\Instances\PYAS Instance", "Flags", winreg.REG_DWORD, 0)

            started, start_error = self._start_driver_service()
            if not started:
                self.write_log("WARN", "Driver Service", detail=f"StartServiceW failed: 0x{start_error & 0xFFFFFFFF:08X}", success=False)
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

            detail = "Driver entered unload-retry state during startup" if final_state == 4 else "Driver did not reach running state"
            self.write_log("WARN", "Driver Protection", detail=detail, success=False)
            return False

        except Exception as e:
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
            return None

    def _connect_driver_port(self, asynchronous=False):
        temp_port = ctypes.wintypes.HANDLE()
        status = self.fltlib.FilterConnectCommunicationPort(
            "\\PYAS_Output_Pipe",
            0 if asynchronous else FLT_PORT_FLAG_SYNC_HANDLE,
            None,
            0,
            None,
            ctypes.byref(temp_port)
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
                return self.driver_listener_ready_event.is_set() and not self.driver_stop_event.is_set()

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
                        ctypes.byref(bytes_returned)
                    )
                except Exception as e:
                    self.write_log("WARN", "Driver Unload Authorization", detail=str(e), success=False)
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
                    ctypes.byref(bytes_returned)
                )
                if status == 0 and bytes_returned.value == ctypes.sizeof(state):
                    return int(state.value)
            except Exception:
                pass
            finally:
                if local_port:
                    try:
                        self.kernel32.CloseHandle(local_port)
                    except Exception:
                        pass

            if use_existing:
                self._close_driver_port(port)

        return None

    def _enable_token_privilege(self, privilege_name):
        token = ctypes.wintypes.HANDLE()
        desired_access = 0x0020 | 0x0008

        if not self.advapi32.OpenProcessToken(self.kernel32.GetCurrentProcess(), desired_access, ctypes.byref(token)):
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
            ctypes.byref(return_length)
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
                self.advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(previous_state), 0, None, None)
        finally:
            self.kernel32.CloseHandle(token)

    def _filter_unload_with_privilege(self, filter_name):
        result = {
            "status": None,
            "privilege_error": 0,
            "authorization_failed": False,
            "exception": None,
            "attempts": 0
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
                        revoked = False
                unload_authorized = not revoked

                if (unload_status & 0xFFFFFFFF) not in retryable_statuses:
                    return result

            if result["status"] is None:
                result["authorization_failed"] = True

        except Exception as e:
            result["exception"] = str(e)
        finally:
            if unload_authorized and self.check_system_driver():
                try:
                    self._set_driver_unload_authorization(False)
                except Exception:
                    pass

            self._restore_token_privilege(privilege_state)

        return result

    def stop_system_driver(self):
        with self.lock_driver_unload:
            runtime_unloaded = False
            unload_confirmed = False
            try:
                if not self._stop_driver_listener():
                    self.write_log("WARN", "Driver Protection", detail="Driver listener cancellation did not complete", success=False)
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
                            self.write_log("WARN", "Driver Protection", detail="Control port unavailable", success=False)
                            return False

                    if not runtime_unloaded:
                        unload_result = self._filter_unload_with_privilege("PYAS_Driver")

                        if unload_result["privilege_error"]:
                            error = unload_result["privilege_error"]
                            self.write_log("WARN", "Driver Protection", detail=f"SeLoadDriverPrivilege unavailable: 0x{error & 0xFFFFFFFF:08X}", success=False)
                            return False

                        if unload_result["authorization_failed"]:
                            self.write_log("WARN", "Driver Protection", detail="Unload authorization rejected", success=False)
                            return False

                        if unload_result["exception"]:
                            self.write_log("WARN", "stop_system_driver", detail=unload_result["exception"], success=False)
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
                            self.write_log("WARN", "Driver Protection", detail=f"FilterUnload failed after {attempts} attempt(s): 0x{unload_status & 0xFFFFFFFF:08X}", success=False)
                            return False

                self._close_driver_port()

                if unload_confirmed:
                    deadline = time.monotonic() + 0.5
                    while time.monotonic() < deadline and self.check_system_driver():
                        time.sleep(0.01)

                    if self.check_system_driver():
                        self.write_log("INFO", "Driver Protection", detail="Filter unloaded; SCM state is still settling")

                return runtime_unloaded
            except Exception as e:
                self.write_log("WARN", "stop_system_driver", detail=str(e), success=False)
                return False
            finally:
                if not runtime_unloaded and self.check_system_driver():
                    self._resume_driver_listener()

    def check_system_driver(self):
        state = self._query_driver_service_state()
        return state in (2, 3, 4)

    def clear_driver_rules(self):
        with self.lock_driver:
            if not self.driver_port:
                return False

            msg = PYAS_USER_MESSAGE()
            msg.Command = 4
            msg.Path = ""
            bytes_returned = ctypes.wintypes.DWORD(0)

            try:
                return self.fltlib.FilterSendMessage(
                    self.driver_port,
                    ctypes.byref(msg),
                    ctypes.sizeof(msg),
                    None,
                    0,
                    ctypes.byref(bytes_returned)
                ) == 0
            except Exception:
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
                return self.fltlib.FilterSendMessage(
                    self.driver_port,
                    ctypes.byref(msg),
                    ctypes.sizeof(msg),
                    None,
                    0,
                    ctypes.byref(bytes_returned)
                ) == 0
            except Exception:
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
                port,
                ctypes.byref(overlapped),
                ctypes.byref(transferred),
                False
            )
            return True
        except Exception:
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
                ctypes.byref(overlapped)
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
                    port,
                    ctypes.byref(overlapped),
                    ctypes.byref(transferred),
                    False
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
                        self.sync_driver_whitelist(item["file"], True)

                if self.driver_stop_event.is_set():
                    break

                ready = True
                self.driver_listener_ready_event.set()

                while self._driver_listener_should_run():
                    with self.lock_driver:
                        current_port = self.driver_port
                        owns_current = self._driver_handle_value(current_port) == self._driver_handle_value(owned_port)

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
                            success=True
                        )

                self._close_driver_port(owned_port)
                owned_port = None
                ready = False
                self.driver_listener_ready_event.clear()

                if self.driver_stop_event.is_set():
                    break
                self.driver_stop_event.wait(0.02)
        except Exception as e:
            self.driver_listener_failed_event.set()
            if not self.driver_stop_event.is_set():
                self.write_log("WARN", "pipe_server_thread", detail=str(e), success=False)
        finally:
            if owned_port:
                try:
                    self.kernel32.CancelIoEx(owned_port, None)
                except Exception:
                    pass
                self._close_driver_port(owned_port)

            if not ready and not self.driver_stop_event.is_set():
                self.driver_listener_failed_event.set()

            self.driver_listener_ready_event.clear()
            with self.lock_driver:
                if self.driver_listener_thread is threading.current_thread():
                    self.driver_listener_thread = None

