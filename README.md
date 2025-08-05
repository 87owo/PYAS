# PYAS (Python Antivirus Software)

![PYAS_UI](https://github.com/user-attachments/assets/68765836-7272-482f-b8cd-d8ba728d88ab)

## Readme Language

繁體中文 : https://github.com/87owo/PYAS/blob/main/README_zh_TW.md

简体中文 : https://github.com/87owo/PYAS/blob/main/README_zh_CN.md

## Requirements

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

## File Information

```
PYAS/
├── PYAS.py                  # Main application (PySide6 GUI interface)
├── PYAS_Config.py           # Configuration handling and global parameters
├── PYAS_Engine.py           # Scanning engine (integrates YARA & ONNX AI detection)
├── PYAS_Interface.py        # User interface definitions and widget logic
├── PYAS_Resource.py         # Static resource management
├── PYAS_Version.py          # Packaging and version info
├── Engine/
│   ├── Models/              # Directory for ONNX AI models
│   └── Rules/               # Directory for YARA and network rules
├── Plugins/
│   └── Filter/              # Driver directory
│       └── PYAS_Driver.sys  # Windows kernel driver for security protection
└── ...                      # Other supplementary folders and files
```

## Official Website

https://pyantivirus.wixsite.com/pyas

https://github.com/87owo/PYAS

## Microsoft Runtime

https://github.com/87owo/Microsoft_Runtime/releases

## MIT license

https://github.com/87owo/PYAS/blob/main/LICENSE.md

## Support System

Windows 10, 11 (64-bit), Ram 500MB, Rom 200MB or higher

Other systems may experience software malfunctions or crash

## Special Thanks

Wix, mtkiao129, 0sha0, AV-T Team of LisectGroup

Copyright© 2020~2025 PYAS Security By 87owo
