# PYAS

以 Python 開發的防毒軟體，結合深度學習與行為監控來阻擋威脅！

![PYAS_UI](https://github.com/user-attachments/assets/68765836-7272-482f-b8cd-d8ba728d88ab)

## 說明語言

English : https://github.com/87owo/PYAS/blob/main/README.md

繁體中文 : https://github.com/87owo/PYAS/blob/main/README_zh_TW.md

简体中文 : https://github.com/87owo/PYAS/blob/main/README_zh_CN.md

## 安裝需求

建議使用 Python 3.10。其他版本的 Python 可能需要不同的 pip 指令。

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

以下列出所有相關程式碼與文件的存放位置。

```
PYAS/
├── Engine/
│   ├── Models/              # ONNX 深度學習模型目錄
│   └── Rules/               # YARA 與網路規則目錄
│
├── Plugins/
│   └── Filter/              # 用於安全防護的 Windows 核心驅動程式
│
├── PYAS.py                  # 主程式與圖形介面 (GUI)
├── PYAS_Config.py           # 組態處理與全域參數
├── PYAS_Engine.py           # YARA 與 ONNX 掃描引擎
├── PYAS_Interface.py        # 使用者介面定義與元件邏輯
├── PYAS_Resource.py         # 靜態圖片資源管理
├── PYAS_Version.py          # 打包與版本資訊
└── ...                      # 其他補充資料夾與檔案
```

## 安裝版本

打包發行版下載：https://github.com/87owo/PYAS/releases

## 系統需求

| 配置需求 | 權限需求    | 系統需求        | 可用記憶體 | 可用儲存空間 |
| ---- | ------- | ----------- | ----- | ------ |
| 最低 | 系統管理員 | Windows 10  | 200MB | 100MB  |
| 建議 | 系統管理員 | Windows 10  | 300MB | 200MB  |
| 最佳 | 系統管理員 | Windows 11  | 500MB | 200MB  |

## 官方網站

官方網站 : https://pyantivirus.wixsite.com/pyas

開源網站 : https://github.com/87owo/PYAS

## 授權條款

https://github.com/87owo/PYAS/blob/main/LICENSE.md
