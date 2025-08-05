# PYAS (Python 防毒軟體)

![PYAS_UI](https://github.com/user-attachments/assets/68765836-7272-482f-b8cd-d8ba728d88ab)

## 安裝要求

```
pip install numpy==1.26.4
pip install onnxruntime==1.18.1
pip install pefile==2023.2.7
pip install Pillow==11.0.0
pip install pyperclip==1.9.0
pip install PySide6==6.9.1
pip install requests==2.32.4
pip install yara-python==4.5.4
```

## 檔案資訊

```
PYAS/
├── PYAS.py                  # 主程式，提供 PySide6 視覺化操作介面
├── PYAS_Config.py           # 設定檔處理與全域參數管理
├── PYAS_Engine.py           # 掃描引擎，整合 YARA 規則與 ONNX AI 模型
├── PYAS_Interface.py        # UI 介面定義與元件交互
├── PYAS_Resource.py         # 資源檔與靜態資源管理
├── PYAS_Version.py          # 程式版本與打包資訊
├── Engine/
│   ├── Models/              # AI 模型（ONNX 格式）存放目錄
│   └── Rules/               # YARA 規則與網路規則存放目錄
├── Plugins/
│   └── Filter/              # 驅動程式目錄
│       └── PYAS_Driver.sys  # Windows 驅動程式（系統保護用）
└── ...                      # 其它輔助資料夾與檔案
```

## 官方網頁

https://pyantivirus.wixsite.com/pyas

https://github.com/87owo/PYAS

## 微軟運行庫

https://github.com/87owo/Microsoft_Runtime/releases

## 開源協議

https://github.com/87owo/PYAS/blob/main/LICENSE.md

## 支援系統

Windows 10, 11 (64-bit),記憶體 500MB, 磁碟容量 200MB 或更高

其他系統或版本可能會遇到軟體功能故障或程序崩潰

## 特別感謝

Wix, mtkiao129, 0sha0, AV-T Team of LisectGroup

Copyright© 2020~2025 PYAS Security By 87owo
