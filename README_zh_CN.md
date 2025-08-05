# PYAS (Python 杀毒软件)

![PYAS_UI](https://github.com/user-attachments/assets/68765836-7272-482f-b8cd-d8ba728d88ab)

## 安装要求

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

## 文件信息

```
PYAS/
├── PYAS.py                  # 主程序，提供 PySide6 视觉化操作介面
├── PYAS_Config.py           # 设定档处理与全域参数管理
├── PYAS_Engine.py           # 扫描引擎，整合 YARA 规则与 ONNX AI 模型
├── PYAS_Interface.py        # UI 介面定义与元件交互
├── PYAS_Resource.py         # 资源档与静态资源管理
├── PYAS_Version.py          # 程式版本与打包资讯
├── Engine/
│   ├── Models/              # AI 模型（ONNX 格式）存放目录
│   └── Rules/               # YARA 规则与网路规则存放目录
├── Plugins/
│   └── Filter/              # 驱动程式目录
│       └── PYAS_Driver.sys  # Windows 驱动程式（系统保护用）
└── ...                      # 其它辅助资料夹与档案
```

## 官方网页

https://pyantivirus.wixsite.com/pyas

https://github.com/87owo/PYAS

## 微软运行库

https://github.com/87owo/Microsoft_Runtime/releases

## 开源协议

https://github.com/87owo/PYAS/blob/main/LICENSE.md

## 支援系统

Windows 10, 11 (64-bit), 内存 500MB, 存储 200MB 或更高

其他系统或版本可能会遇到软体功能故障或程序崩溃

## 特别感谢

Wix, mtkiao129, 0sha0, AV-T Team of LisectGroup

Copyright© 2020~2025 PYAS Security By 87owo
