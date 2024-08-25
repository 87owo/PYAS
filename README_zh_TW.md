# PYAS (Python 防毒軟體)

![PYAS](https://github.com/user-attachments/assets/39c273b9-c467-480a-a8b3-31714a6df3ef)

## 安裝要求

```
psutil==5.9.5
pefile==2023.2.7
requests==2.31.0
pyperclip==1.8.2
pywin32==306
PyQt5==5.15.9
```

## 檔案資訊

```
PYAS/
├── Driver/
│   ├── PYAS_Driver.sys -------> 驅動程式 (0sha0 為 pyas 提供的自我保護驅動程式)
│   └── ...
│
├── Model/
│   ├── PYAS_Model.json -------> 病毒資料庫 (資料庫必須位於指定目錄)
│   └── ...
│
├── Rules/
│   ├── Yara_Rules.yar ---------> Yara 規則 (純文字格式的 yara 規則)
│   ├── Yara_Rules.yrc ---------> 編譯規則 (編譯格式的 yara 規則)
│   └── ...
│
├── PYAS.py ---------------------> PYAS主程式（包含動畫、掃描、保護等功能...）
├── PYAS_Engine.py -------------> 轉換資料庫（用於轉換剖面圖和預報資料）
├── PYAS_Suffixes.py -----------> 文件後綴（包含掃描文件後綴和常用後綴）
├── PYAS_Interface.py ----------> PyQt5介面（使用QT設計器，需與主程式搭配使用）
├── PYAS_Resource.py -----------> PyQt5資源（狀態圖片、圖示包、按鈕圖示...）
├── PYAS_Language.py -----------> 翻譯字典（繁體中文、簡體中文、英文）
├── PYAS_Version.py ------------> 安裝資訊（檔案資訊、版本資訊、原名...）
└── ...
```

## 官方網頁

https://pyantivirus.wixsite.com/pyas

https://github.com/87owo/PYAS

## 微軟運行庫

https://github.com/87owo/Microsoft_Runtime/releases

## 驅動程式

https://github.com/0sha0/PYAS_Protection

## 開源協議

https://github.com/87owo/PYAS/blob/main/LICENSE.md

## 支援系統

Windows 8.1, 10, 11 (64-bit),記憶體 500MB, 磁碟容量 200MB 或更高

其他系統或版本可能會遇到軟體功能故障或程序崩潰

## 特別感謝

Wix, 0sha0, mtkiao129, AV-T Team of LisectGroup

Copyright© 2020~2024 PYAS Security By 87owo
