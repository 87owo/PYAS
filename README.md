# PYAS (Python Antivirus Software)

![PYAS](https://github.com/87owo/PYAS/assets/85057800/8136aaca-d388-4321-bedb-abc4fcecfa8b)

## Readme Language

[繁體中文](https://github.com/87owo/PYAS/blob/main/README_zh_TW.md) , 
[简体中文](https://github.com/87owo/PYAS/blob/main/README_zh_CN.md)

## File Information

PYAS.py -> Main PYAS Program (including animation, scanning, protection functions, etc.)

PYAS_Engine.py -> Conversion Database (used to convert database dict and list to and from each other)

PYAS_Extension.py -> File Extension (including scanned file extensions and common file extensions)

PYAS_Model.* -> Virus Database (the virus database must be placed in the same directory)

PYAS_Interface.py -> PyQt5 Interface (designed by QT designer, must be matched with the main program)

PYAS_Resource.py -> PyQt5 Resource (status pictures, icon packages, button icons, etc.)

PYAS_Language.py -> Translate Dict (Traditional Chinese, Simplified Chinese, English)

PYAS_Version.py -> Pyinstaller Info (file information, version information, original name, etc.)

## Dir Information

```
PYAS/
├── Model/
│   ├── PYAS_Model.json
│   ├── PYAS_Model.txt
│   └── ...
│
├── Rules/
│   ├── Yara_Rules.yar
│   ├── Compile_Rules.yrc
│   └── ...
│
├── PYAS.py
├── PYAS_Engine.py
└── ...
```

## Requirements

Use pip install requirements to install import module

```
psutil==5.9.5
pefile==2023.2.7
requests==2.31.0
pyperclip==1.8.2
pywin32==306
PyQt5==5.15.9
```

## Pefile Scanning

Get the pefile file function import table for scanning

```
import pefile

def pe_scan(file):
    try:
        fn = []
        with pefile.PE(file) as pe:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for func in entry.imports:
                    try:
                        fn.append(str(func.name, "utf-8"))
                    except:
                        pass
            if fn in known_malicious_list:
                return "Virus"
            return "Safe"
        return "Unknown"
    except Exception as e:
        return f"Error: {e}"

info = pe_scan("path to file")
print(info)
```

## Process Detect

Show the new process name, file path, cmd line, pid

```
import psutil, time

def proc_detect():
    existing_processes = set()
    for p in psutil.process_iter():
        if p.pid not in existing_processes:
            existing_processes.add(p.pid)
    while True:
        time.sleep(0.1)
        for p in psutil.process_iter():
            try:
                if p.pid not in existing_processes:
                    existing_processes.add(p.pid)
                    name, file, cmd = p.name(), p.exe(), p.cmdline()
                    print(f"Name: {name}")
                    print(f"File: {file}")
                    print(f"Pid: {p.pid}")
                    print(f"Cmd: {cmd}")
                elif not psutil.pid_exists(p.pid):
                    existing_processes.remove(p.pid)
            except:
                pass

proc_detect()
```

## File Detect

Monitor file changes under the specified path

```
import os, win32file, win32con

def file_detect(path):
    hDir = win32file.CreateFile(path,win32con.GENERIC_READ,win32con.FILE_SHARE_READ|win32con.FILE_SHARE_WRITE|win32con.FILE_SHARE_DELETE,None,win32con.OPEN_EXISTING,win32con.FILE_FLAG_BACKUP_SEMANTICS,None)
    while True:
        for action, file in win32file.ReadDirectoryChangesW(hDir,10485760,True,win32con.FILE_NOTIFY_CHANGE_FILE_NAME|win32con.FILE_NOTIFY_CHANGE_DIR_NAME|win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES|win32con.FILE_NOTIFY_CHANGE_SIZE|win32con.FILE_NOTIFY_CHANGE_LAST_WRITE|win32con.FILE_NOTIFY_CHANGE_SECURITY,None,None):
            try:
                fpath = os.path.join(path, file)
                if action == 1:
                    print(f"File Create: {fpath}")
                elif action == 2:
                    print(f"File Delete: {fpath}")
                elif action == 3:
                    print(f"File Modify: {fpath}")
                elif action == 4:
                    print(f"File Rename: {fpath}")
                elif action == 5:
                    print(f"File Rename: {fpath}")
            except:
                pass

file_detect("path")
```

## Official Website

https://pyantivirus.wixsite.com/pyas

https://github.com/87owo/PYAS

## MIT license

https://github.com/87owo/PYAS/blob/main/LICENSE.md

## Support System

Windows 8.1, 10, 11 (64-bit), Ram 500MB, Rom 200MB or higher

Other systems may experience software malfunctions or crash

## Special Thanks

360, Wix, VirusShare, mtkiao129, AV-T Team of LisectGroup

Copyright© 2020~2024 PYAS Security By 87owo
