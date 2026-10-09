from PYAS_Diagnostics import log_exception
import os
import io
import csv
import json
import sys
import winreg
import subprocess
import ctypes
import ctypes.wintypes
from concurrent.futures import ThreadPoolExecutor


class AutostartMixin:
    def _set_registry_autostart(self, enable):
        run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        value_name = "PYAS_Security"

        if enable:
            command = f'"{self.file_pyas}" -hide'
            return self._reg_write(
                winreg.HKEY_CURRENT_USER, run_key, value_name, winreg.REG_SZ, command
            )

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_SET_VALUE) as reg:
                try:
                    winreg.DeleteValue(reg, value_name)
                except FileNotFoundError:
                    pass

            return True
        except FileNotFoundError:
            return True
        except Exception:
            log_exception("PYAS_Autostart.AutostartMixin._set_registry_autostart:25")
            return False

    def _get_autostart_user_sid(self):
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        user32.GetShellWindow.restype = ctypes.wintypes.HWND
        user32.GetWindowThreadProcessId.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.POINTER(ctypes.wintypes.DWORD),
        ]
        user32.GetWindowThreadProcessId.restype = ctypes.wintypes.DWORD
        kernel32.OpenProcess.argtypes = [
            ctypes.wintypes.DWORD,
            ctypes.wintypes.BOOL,
            ctypes.wintypes.DWORD,
        ]
        kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        advapi32.OpenProcessToken.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.DWORD,
            ctypes.POINTER(ctypes.wintypes.HANDLE),
        ]
        advapi32.GetTokenInformation.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.wintypes.DWORD,
            ctypes.POINTER(ctypes.wintypes.DWORD),
        ]
        advapi32.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        hwnd = user32.GetShellWindow()

        if not hwnd:
            raise OSError("No interactive Windows desktop is available for autostart")

        pid = ctypes.wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        process = kernel32.OpenProcess(0x1000, False, pid.value)

        if not process:
            raise ctypes.WinError(ctypes.get_last_error())

        token = ctypes.wintypes.HANDLE()
        sid_string = ctypes.c_void_p()

        try:
            if not advapi32.OpenProcessToken(process, 0x0008, ctypes.byref(token)):
                raise ctypes.WinError(ctypes.get_last_error())

            size = ctypes.wintypes.DWORD()
            advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))

            if not size.value:
                raise ctypes.WinError(ctypes.get_last_error())

            buffer = ctypes.create_string_buffer(size.value)

            if not advapi32.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())

            sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents

            if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(sid_string)):
                raise ctypes.WinError(ctypes.get_last_error())

            return ctypes.wstring_at(sid_string)
        finally:
            if sid_string.value:
                kernel32.LocalFree(sid_string)

            if token.value:
                kernel32.CloseHandle(token)

            kernel32.CloseHandle(process)

    def _autostart_task_script(self, enable, sid):
        executable = self.file_pyas if getattr(sys, "frozen", False) else sys.executable
        arguments = (
            "-hide"
            if getattr(sys, "frozen", False)
            else subprocess.list2cmdline([self.file_pyas, "-hide"])
        )
        quote = lambda value: "'" + value.replace("'", "''") + "'"
        values = (
            "$ErrorActionPreference = 'Stop'; "
            "[Console]::OutputEncoding = [Text.UTF8Encoding]::new(); "
            f"$Sid = {quote(sid)}; $Executable = {quote(os.path.normpath(executable))}; "
            f"$Arguments = {quote(arguments)}; $WorkingDirectory = {quote(os.path.dirname(self.file_pyas))}; "
            f"$Enable = {'$true' if enable else '$false'}; "
        )
        return (
            values
            + r"""
function Resolve-Sid($UserId) {
    if ($UserId -like 'S-1-*') { return $UserId }
    return ([Security.Principal.NTAccount]::new($UserId)).Translate([Security.Principal.SecurityIdentifier]).Value
}
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($Identity.User.Value -ne $Sid) {
    throw 'The elevated account differs from the signed-in desktop user. Configure autostart while signed in as the target administrator.'
}
if (-not ([Security.Principal.WindowsPrincipal]::new($Identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required to configure elevated autostart.'
}
$Service = New-Object -ComObject 'Schedule.Service'
$Service.Connect()
$Folder = $Service.GetFolder('\')
$TaskName = 'PYAS_Security_ATS_' + $Sid
function Find-Task($Name) {
    foreach ($Task in $Folder.GetTasks(1)) {
        if ($Task.Name -eq $Name) { return $Task }
    }
    return $null
}
function Save-Task($Task) {
    $BackupDirectory = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'PYAS\StartupTasks'
    [IO.Directory]::CreateDirectory($BackupDirectory) | Out-Null
    $BackupPath = Join-Path $BackupDirectory ($Task.Name + '-' + [Guid]::NewGuid().ToString('N') + '.xml')
    [IO.File]::WriteAllText($BackupPath, $Task.Xml, [Text.Encoding]::UTF8)
}
function Test-Task($Task) {
    if (-not $Task -or -not $Task.Enabled) { return $false }
    $Definition = $Task.Definition
    if ($Definition.Actions.Count -ne 1 -or $Definition.Triggers.Count -ne 1) { return $false }
    $Action = $Definition.Actions.Item(1)
    $Trigger = $Definition.Triggers.Item(1)
    $Settings = $Definition.Settings
    return ((Resolve-Sid $Definition.Principal.UserId) -eq $Sid -and
        $Definition.Principal.LogonType -eq 3 -and $Definition.Principal.RunLevel -eq 1 -and
        $Action.Type -eq 0 -and $Action.Path -eq $Executable -and
        $Action.Arguments -eq $Arguments -and $Action.WorkingDirectory -eq $WorkingDirectory -and
        $Trigger.Type -eq 9 -and $Trigger.Enabled -and (Resolve-Sid $Trigger.UserId) -eq $Sid -and
        $Trigger.Delay -eq 'PT10S' -and -not $Settings.DisallowStartIfOnBatteries -and
        -not $Settings.StopIfGoingOnBatteries -and $Settings.ExecutionTimeLimit -eq 'PT0S' -and
        $Settings.MultipleInstances -eq 2 -and $Settings.RestartCount -eq 3 -and
        $Settings.RestartInterval -eq 'PT1M')
}
$Existing = Find-Task $TaskName
$ExistingXml = if ($Existing) { $Existing.Xml } else { $null }
if ($Enable) {
    if (-not (Test-Task $Existing)) {
        if ($Existing) { Save-Task $Existing }
        $Definition = $Service.NewTask(0)
        $Definition.RegistrationInfo.Description = 'PYAS elevated autostart for the signed-in user'
        $Definition.Principal.UserId = $Sid
        $Definition.Principal.LogonType = 3
        $Definition.Principal.RunLevel = 1
        $Trigger = $Definition.Triggers.Create(9)
        $Trigger.UserId = $Sid
        $Trigger.Delay = 'PT10S'
        $Trigger.Enabled = $true
        $Action = $Definition.Actions.Create(0)
        $Action.Path = $Executable
        $Action.Arguments = $Arguments
        $Action.WorkingDirectory = $WorkingDirectory
        $Definition.Settings.Enabled = $true
        $Definition.Settings.DisallowStartIfOnBatteries = $false
        $Definition.Settings.StopIfGoingOnBatteries = $false
        $Definition.Settings.ExecutionTimeLimit = 'PT0S'
        $Definition.Settings.MultipleInstances = 2
        $Definition.Settings.RestartCount = 3
        $Definition.Settings.RestartInterval = 'PT1M'
        try {
            $Folder.RegisterTaskDefinition($TaskName, $Definition, 6, $Sid, $null, 3) | Out-Null
            if (-not (Test-Task (Find-Task $TaskName))) { throw 'Autostart task verification failed' }
        } catch {
            $Failure = $_
            if ($Existing) {
                $Folder.RegisterTask($TaskName, $ExistingXml, 6, $Sid, $null, 3) | Out-Null
            } else {
                $Created = Find-Task $TaskName
                if ($Created) { $Folder.DeleteTask($TaskName, 0) }
            }
            throw $Failure
        }
    }
} elseif ($Existing) {
    Save-Task $Existing
    $Folder.DeleteTask($TaskName, 0)
    if (Find-Task $TaskName) { throw 'Autostart task removal verification failed' }
}
$Legacy = Find-Task 'PYAS_Security_ATS'
if ($Legacy -and (Resolve-Sid $Legacy.Definition.Principal.UserId) -eq $Sid -and
    $Legacy.Definition.Actions.Count -eq 1 -and $Legacy.Definition.Actions.Item(1).Path -eq $Executable) {
    Save-Task $Legacy
    $Folder.DeleteTask($Legacy.Name, 0)
}
@{verified=$true; taskName=$TaskName; userSid=$Sid; enabled=$Enable} | ConvertTo-Json -Compress
"""
        )

    def manage_autostart(self, enable):
        try:
            sid = self._get_autostart_user_sid()
            command = self._autostart_task_script(enable, sid)
            result = self._run_powershell(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )

            if result is None:
                raise OSError("PowerShell is unavailable; elevated autostart cannot be configured")

            if result.returncode != 0:
                raise OSError(
                    (
                        result.stderr or result.stdout or f"PowerShell exit {result.returncode}"
                    ).strip()
                )

            state = json.loads(result.stdout)

            if (
                state.get("verified") is not True
                or state.get("userSid") != sid
                or state.get("taskName") != "PYAS_Security_ATS_" + sid
                or state.get("enabled") is not bool(enable)
            ):
                raise OSError("Autostart task readback did not match the requested state")

            if not self._set_registry_autostart(False):
                raise OSError("The legacy HKCU Run entry could not be removed")

            self.autostart_mode = "task" if enable else "disabled"
            self.write_log(
                "INFO",
                "manage_autostart",
                detail=f"Verified {self.autostart_mode}: {state['taskName']}",
                success=True,
            )
            return True
        except Exception as e:
            log_exception("PYAS_Autostart.AutostartMixin.manage_autostart:201")
            self.autostart_mode = "unavailable"
            self.write_log("WARN", "manage_autostart", detail=str(e), success=False)
            return False

    def get_startup_list(self):
        items = []

        def get_reg_startup():
            res = []
            paths = [
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    "enabled",
                ),
                (
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    "enabled",
                ),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run_Disabled",
                    "disabled",
                ),
                (
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run_Disabled",
                    "disabled",
                ),
            ]

            for root, path, status in paths:
                try:
                    with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as reg:
                        i = 0

                        while True:
                            try:
                                name, val, _ = winreg.EnumValue(reg, i)
                                file_path = self.extract_paths_from_cmdline(val)
                                fp = file_path[0] if file_path else val
                                res.append(
                                    {
                                        "id": f"reg|{root}|{path}|{name}",
                                        "type": "type_reg",
                                        "name": name,
                                        "status": status,
                                        "path": fp,
                                    }
                                )
                                i += 1

                            except OSError:
                                log_exception(
                                    "PYAS_Autostart.AutostartMixin.get_startup_list.get_reg_startup:230"
                                )
                                break
                except Exception:
                    log_exception(
                        "PYAS_Autostart.AutostartMixin.get_startup_list.get_reg_startup:232"
                    )
                    pass

            return res

        def get_services():
            res = []

            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services",
                    0,
                    winreg.KEY_READ,
                ) as reg:
                    i = 0

                    while True:
                        try:
                            name = winreg.EnumKey(reg, i)
                            i += 1

                            try:
                                with winreg.OpenKey(reg, name, 0, winreg.KEY_READ) as sub:
                                    stype, _ = winreg.QueryValueEx(sub, "Type")

                                    if stype not in (16, 32, 256):
                                        continue

                                    start, _ = winreg.QueryValueEx(sub, "Start")

                                    if start not in (2, 3, 4):
                                        continue

                                    path, _ = winreg.QueryValueEx(sub, "ImagePath")

                                    if (
                                        path
                                        and "svchost" not in path.lower()
                                        and "windows" not in path.lower()
                                    ):
                                        fp = self.extract_paths_from_cmdline(path)
                                        fpp = fp[0] if fp else path
                                        status = "enabled" if start == 2 else "disabled"
                                        res.append(
                                            {
                                                "id": f"srv|{name}",
                                                "type": "type_srv",
                                                "name": name,
                                                "status": status,
                                                "path": fpp,
                                            }
                                        )

                            except Exception:
                                log_exception(
                                    "PYAS_Autostart.AutostartMixin.get_startup_list.get_services:262"
                                )
                                pass
                        except OSError:
                            log_exception(
                                "PYAS_Autostart.AutostartMixin.get_startup_list.get_services:264"
                            )
                            break

            except Exception:
                log_exception("PYAS_Autostart.AutostartMixin.get_startup_list.get_services:267")
                pass

            return res

        def get_tasks():
            res = []

            try:
                proc = self._run_windows_tool(
                    ("schtasks.exe",),
                    ["/query", "/fo", "csv", "/v"],
                    capture_output=True,
                    text=True,
                )

                if proc is not None and proc.returncode == 0:
                    reader = csv.reader(io.StringIO(proc.stdout))
                    next(reader, None)

                    for row in reader:
                        if len(row) > 8 and row[1].strip() and row[8].strip() and row[8] != "N/A":
                            name = row[1].split("\\")[-1]
                            path = row[8]
                            status = row[3]

                            if path and "windows" not in path.lower():
                                fp = self.extract_paths_from_cmdline(path)
                                fpp = fp[0] if fp else path
                                res.append(
                                    {
                                        "id": f"tsk|{row[1]}",
                                        "type": "type_tsk",
                                        "name": name,
                                        "status": (
                                            "disabled"
                                            if status.lower() == "disabled"
                                            else "enabled"
                                        ),
                                        "path": fpp,
                                    }
                                )

                    return res

                command = (
                    "[Console]::OutputEncoding = [Text.UTF8Encoding]::new(); "
                    "Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { "
                    "$Action = @($_.Actions)[0]; "
                    "[pscustomobject]@{Name=$_.TaskName; FullName=($_.TaskPath + $_.TaskName); "
                    "State=[string]$_.State; Execute=$Action.Execute; Arguments=$Action.Arguments} "
                    "} | ConvertTo-Json -Compress"
                )
                proc = self._run_powershell(
                    command, capture_output=True, text=True, encoding="utf-8", errors="replace"
                )

                if not proc or proc.returncode != 0 or not proc.stdout.strip():
                    return res

                task_data = json.loads(proc.stdout)

                if isinstance(task_data, dict):
                    task_data = [task_data]

                for task in task_data:
                    name = str(task.get("Name") or "").strip()
                    full_name = str(task.get("FullName") or name).strip()
                    execute = str(task.get("Execute") or "").strip()
                    arguments = str(task.get("Arguments") or "").strip()
                    command_line = " ".join(part for part in (execute, arguments) if part)

                    if not name or not command_line or "windows" in command_line.lower():
                        continue

                    paths = self.extract_paths_from_cmdline(command_line)
                    path = paths[0] if paths else execute or command_line
                    status = (
                        "disabled"
                        if str(task.get("State") or "").lower() == "disabled"
                        else "enabled"
                    )
                    res.append(
                        {
                            "id": f"tsk|{full_name}",
                            "type": "type_tsk",
                            "name": name,
                            "status": status,
                            "path": path,
                        }
                    )

            except Exception:
                log_exception("PYAS_Autostart.AutostartMixin.get_startup_list.get_tasks:326")
                pass

            return res

        with ThreadPoolExecutor(max_workers=3) as executor:
            f1 = executor.submit(get_reg_startup)
            f2 = executor.submit(get_services)
            f3 = executor.submit(get_tasks)

            items.extend(f1.result())
            items.extend(f2.result())
            items.extend(f3.result())

        return items

    def manage_startup(self, items, action):
        def process_item(item_id):
            try:
                parts = item_id.split("|", 3)
                stype = parts[0]

                if stype == "reg":
                    root, old_path, name = int(parts[1]), parts[2], parts[3]

                    if action == "delete":
                        return self._reg_delete(root, old_path, name)

                    else:
                        new_path = (
                            old_path.replace("_Disabled", "")
                            if action == "enable"
                            else (old_path if "_Disabled" in old_path else old_path + "_Disabled")
                        )

                        if old_path != new_path:
                            with winreg.OpenKey(root, old_path, 0, winreg.KEY_READ) as reg:
                                val, value_type = winreg.QueryValueEx(reg, name)

                            return self._reg_write(
                                root, new_path, name, value_type, val
                            ) and self._reg_delete(root, old_path, name)

                        return True

                elif stype == "srv":
                    name = parts[1]

                    if action == "delete":
                        result = self._run_windows_tool(
                            ("sc.exe",), ["delete", name], capture_output=True
                        )

                    else:
                        mode = "auto" if action == "enable" else "disabled"
                        result = self._run_windows_tool(
                            ("sc.exe",), ["config", name, "start=", mode], capture_output=True
                        )

                    if result is not None and result.returncode == 0:
                        return True

                    return self._manage_service_native(name, action)

                elif stype == "tsk":
                    name = item_id.partition("|")[2]
                    return self._manage_scheduled_task(name, action)

                return False

            except Exception as e:
                log_exception("PYAS_Autostart.AutostartMixin.manage_startup.process_item:379")
                self.write_log("WARN", "manage_startup", detail=str(e), success=False)
                return False

        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(process_item, items))

        success = all(results) if results else True

        if not success:
            self.write_log(
                "WARN",
                "manage_startup",
                detail="One or more startup items could not be updated",
                success=False,
            )

        return success
