# PYAS

使用 Python 和 C 開發的防毒軟體，並透過深度學習和行為監控來阻止威脅！

<img width="2245" height="1477" alt="PYAS_UI" src="https://github.com/user-attachments/assets/87d40261-7655-49ad-a19c-1ffcca60584f" />

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
│   ├── Models/
│   │   ├── convert.py               # 將可執行檔或其他檔案轉換為圖片
│   │   └── train.py                 # TensorFlow CNN 模型訓練完整程式碼
│   │
│   └── Rules/
│       ├── rules.yar                # YARA 病毒特徵碼規則匹配
│       └── rules.ips                # IP 網路位址規則匹配
│
├── Plugins/
│   └── Filter/
│       ├── DriverEntry.c            # 驅動主入口與初始化邏輯
│       ├── DriverEntry.h            # 全域驅動定義、常數與函式
│       ├── DriverPipe.c             # 核心層與使用者層的管道日誌傳輸實作
│       ├── ProtectBoot.c            # 磁碟開機區寫入保護
│       ├── ProtectImage.c           # 映像載入監控與 shellcode 偵測
│       ├── ProtectInject.c          # 程序與執行緒控制，防止注入
│       ├── ProtectReg.c             # 登錄檔修改保護
│       ├── ProtectRules.c           # 白名單、封鎖清單與檔案/登錄匹配邏輯
│       └── ProtectRules.h           # 保護規則宣告
│
├── PYAS.py                          # 主應用程式入口點與 UI 到引擎的介面
├── PYAS_Config.py                   # 組態載入、儲存與全域參數
├── PYAS_Engine.py                   # 核心掃描引擎：YARA、IP、ONNX 模型執行
├── PYAS_Interface.py                # 使用者介面元件與事件處理
├── PYAS_Resource.py                 # 靜態圖片與圖示資源管理
├── PYAS_Version.py                  # 版本中繼資料，用於打包與更新
└── ...                              # 其他補充資料夾與檔案
```

## 安裝版本

打包發行版下載 : https://github.com/87owo/PYAS/releases

## 系統需求

| 配置要求 | 權限 | 系統版本 | 處理器 | 可用記憶體空間 | 可用儲存空間 |
| ------- | ---- | ------- | ------ | ------------ | ----------- |
| 最低配置 | 管理員 | >= Windows 10 (20H1) | 1 GHz | 200MB | 100MB |
| 推薦配置 | 管理員 | >= Windows 10 (21H2) | 3 GHz | 300MB | 200MB |

## 官方網站

官方網站 : https://pyantivirus.wixsite.com/pyas

開源網站 : https://github.com/87owo/PYAS

## 授權條款

https://github.com/87owo/PYAS/blob/main/LICENSE.txt
