# PYAS (Python 防毒軟體)

![PYAS](https://github.com/87owo/PYAS/assets/85057800/8136aaca-d388-4321-bedb-abc4fcecfa8b)

## 檔案資訊

PYAS.py -> PYAS主程式（包括動畫、掃描、保護功能等）

PYAS_Engine.py -> 轉換資料庫（用於相互轉換資料庫字典和清單）

PYAS_Extension.py -> 檔案副檔名（包括掃描檔案副檔名和常用檔案副檔名）

PYAS_Model.* -> 病毒庫（病毒庫必須放在同一目錄下）

PYAS_Interface.py -> PyQt5 Interface（由QT設計師設計，必須與主程式相符）

PYAS_Resource.py -> PyQt5資源（狀態圖片、圖示包、按鈕圖示等）

PYAS_Language.py -> 翻譯字典（繁體中文、簡體中文、英文）

PYAS_Version.py -> Pyinstaller Info（檔案資訊、版本資訊、原名等）

## 目錄資訊

```
PYAS/
├── Driver/
│   ├── PYAS_Driver.sys
│   └── ...
│
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

## 安裝要求

使用 pip install requirements 來安裝需要的模組

```
psutil==5.9.5
pefile==2023.2.7
requests==2.31.0
pyperclip==1.8.2
pywin32==306
PyQt5==5.15.9
```

## 檔案掃描

取得pefile檔案函數導入表進行掃描

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

## 進程監控

顯示新進程名稱、檔案路徑、cmd 行、pid
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

## 檔案監控

監控指定路徑下的檔案變化
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

## 官方網頁

https://pyantivirus.wixsite.com/pyas

https://github.com/87owo/PYAS

## 開源協議

https://github.com/87owo/PYAS/blob/main/LICENSE.md

## 支援系統

Windows 8.1, 10, 11 (64-bit),記憶體 500MB, 磁碟容量 200MB 或更高

其他系統或版本可能會遇到軟體功能故障或程序崩潰

## 特別感謝

360, Wix, VirusShare, mtkiao129, AV-T Team of LisectGroup

Copyright© 2020~2024 PYAS Security By 87owo
