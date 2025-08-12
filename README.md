# PYAS

Python antivirus software uses deep learning and behavioral monitoring to block threats!

![PYAS_UI](https://github.com/user-attachments/assets/68765836-7272-482f-b8cd-d8ba728d88ab)

## Readme Language

English : https://github.com/87owo/PYAS/blob/main/README.md

繁體中文 : https://github.com/87owo/PYAS/blob/main/README_zh_TW.md

简体中文 : https://github.com/87owo/PYAS/blob/main/README_zh_CN.md

## Requirements

Python 3.10 is recommended. Other Python versions may require different pip commands.

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

The following lists the storage locations of all relevant code and other related documents.

```
PYAS/
├── Engine/
│   ├── Models/              # Directory for ONNX AI models
│   └── Rules/               # Directory for YARA and network rules
│
├── Plugins/
│   └── Filter/              # Windows kernel driver for security protection
│
├── PYAS.py                  # Main application and GUI interface
├── PYAS_Config.py           # Configuration handling and global parameters
├── PYAS_Engine.py           # YARA and ONNX Scanning engine
├── PYAS_Interface.py        # User interface definitions and widget logic
├── PYAS_Resource.py         # Static resource management
├── PYAS_Version.py          # Packaging and version info
└── ...                      # Other supplementary folders and files
```

## Packaged Releases

Packaged Releases Download: https://github.com/87owo/PYAS/releases

## Support System

| Config    | Permissions   | System version | Available memory | Available storage |
|-----------|---------------|----------------|------------------|-------------------|
| Minimum   | Administrator | Windows 8.1    | 200MB            | 100MB             |
| Recommend | Administrator | Windows 10     | 300MB            | 200MB             |
| Optimal   | Administrator | Windows 11     | 500MB            | 200MB             |

## Official Website

https://github.com/87owo/PYAS

## Project License

https://github.com/87owo/PYAS/blob/main/LICENSE.md
