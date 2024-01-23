# PYAS (Python Antivirus Software)

![PYAS](https://github.com/87owo/PYAS/assets/85057800/153bcad9-18ab-4c81-bcb6-186434d0ef1b)

## File Information

PYAS.py -> Main PYAS Program (including animation, scanning, protection functions, etc.)

PYAS_Compress.py -> Conversion Database (used to convert database dict and list to and from each other)

PYAS_Extension.py -> File Extension (including scanned file extensions and common file extensions)

PYAS_Function.* -> Compress Database (need to use zip to decompress and put it in the same directory)

PYAS_Interface.py -> PyQt5 Interface (designed by QT designer, must be matched with the main program)

PYAS_Resource.py -> PyQt5 Resource (status pictures, icon packages, button icons, etc.)

PYAS_Language.py -> Translate Dict (Traditional Chinese, Simplified Chinese, English)

PYAS_Version.py -> Pyinstaller Info (file information, version information, original name, etc.)

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

## Hash Scanning

Use Qihoo 360 cloud service to scan known malicious files

```
import hashlib, requests
import xml.etree.ElementTree as xmlet

def hash_scan(file):
    try:
        with open(file, "rb") as f:
            text = str(hashlib.md5(f.read()).hexdigest())
        strBody = f'-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="md5s"\r\n\r\n{text}\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="format"\r\n\r\nXML\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="product"\r\n\r\n360zip\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="combo"\r\n\r\n360zip_main\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="v"\r\n\r\n2\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="osver"\r\n\r\n5.1\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="vk"\r\n\r\na03bc211\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="mid"\r\n\r\n8a40d9eff408a78fe9ec10a0e7e60f62\r\n-------------------------------7d83e2d7a141e--'
        response = requests.post('http://qup.f.360.cn/file_health_info.php', data=strBody, timeout=3)
        if response.status_code == 200:
            level = float(xmlet.fromstring(response.text).find('.//e_level').text)
            if level > 50:
                return "Virus"
            elif level <= 10:
                return "Safe"
            return "Unknown"
        return f"Error: {response.status_code}"
    except Exception as e:
        return f"Error: {e}"

info = hash_scan("path to file")
print(info)
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

Windows 8.1, 10, 11 (64-bit), Ram 1GB, Rom 1GB or higher

Other systems may experience software malfunctions or crash

## Special Thanks
360, Wix, VirusShare, mtkiao129, AV-T Team of LisectGroup

Copyright© 2020~2024 PYAS Security By 87owo
