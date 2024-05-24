# PYAS (Python 杀毒软件)

![PYAS](https://github.com/87owo/PYAS/assets/85057800/153bcad9-18ab-4c81-bcb6-186434d0ef1b)

## 文件讯息

PYAS.py -> PYAS主程式（包括动画、扫描、保护功能等）

PYAS_Engine.py -> 转换资料库（用于相互转换资料库字典和清单）

PYAS_Extension.py -> 副文件名（包括扫描文件副文件名和常用副文件名）

PYAS_Model.* -> 病毒库（病毒库必须放在同一目录下）

PYAS_Interface.py -> PyQt5 Interface（由QT设计师设计，必须与主程式相符）

PYAS_Resource.py -> PyQt5资源（状态图片、图示包、按钮图示等）

PYAS_Language.py -> 翻译字典（繁体中文、简体中文、英文）

PYAS_Version.py -> Pyinstaller Info（文件资讯、版本资讯、原名等）

## 安装要求

使用 pip install requirements 来安装需要的模组

```
psutil==5.9.5
pefile==2023.2.7
requests==2.31.0
pyperclip==1.8.2
pywin32==306
PyQt5==5.15.9
```

## 文件扫描

取得pefile文件函数导入表进行扫描

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

## 进程监控

显示新进程名称、文件路径、cmd 行、pid

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

## 文件监控

监控指定路径下的文件变化

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

## 官方网页

https://pyantivirus.wixsite.com/pyas

https://github.com/87owo/PYAS

## 开源协议

https://github.com/87owo/PYAS/blob/main/LICENSE.md

## 支援系统

Windows 8.1, 10, 11 (64-bit), 内存 500MB, 存储 200MB 或更高

其他系统或版本可能会遇到软体功能故障或程序崩溃

## 特别感谢

360, Wix, VirusShare, mtkiao129, AV-T Team of LisectGroup

Copyright© 2020~2024 PYAS Security By 87owo
