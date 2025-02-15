# PYAS (Python Antivirus Software)

![PYAS_UI](https://github.com/user-attachments/assets/68765836-7272-482f-b8cd-d8ba728d88ab)

## Readme Language

繁體中文 : https://github.com/87owo/PYAS/blob/main/README_zh_TW.md

简体中文 : https://github.com/87owo/PYAS/blob/main/README_zh_CN.md

## Requirements

```
pip install chardet==5.2.0
pip install numpy==1.26.3
pip install onnxruntime==1.18.1
pip install pefile==2023.2.7
pip install pillow==10.4.0
pip install pyperclip==1.8.2
pip install PyQt5==5.15.11
pip install requests==2.32.3
pip install yara-python==4.5.1
```

## File Information

```
PYAS/
├── Driver/ (Protect driver and Microsoft runtime)
│   └── ...
│
├── Engine/ (Deep learn model and Yara database)
│   └── ...
│
├── Exten/ (Exten tools and System repair tools)
│   └── ...
│
├── PYAS.py (Main PYAS program with qtui interaction and protect function)
├── PYAS_Engine.py (Deep learning predict and yara rules file scanner)
├── PYAS_Suffixes.py (including scan file suffixes and common suffixes)
├── PYAS_Interface.py (Qt designer ui, must be matched with the main program)
├── PYAS_Resource.py (status pictures, icon packages, and button icons)
├── PYAS_Language.py (Traditional Chinese, Simplified Chinese and English)
├── PYAS_Version.py (file information, version information, original name)
└── ...
```

## Official Website

https://pyantivirus.wixsite.com/pyas

https://github.com/87owo/PYAS

## Microsoft Runtime

https://github.com/87owo/Microsoft_Runtime/releases

## PYAS Driver

https://github.com/0sha0/PYAS_Protection

## MIT license

https://github.com/87owo/PYAS/blob/main/LICENSE.md

## Support System

Windows 8.1, 10, 11 (64-bit), Ram 500MB, Rom 200MB or higher

Other systems may experience software malfunctions or crash

## Special Thanks

Wix, mtkiao129, 0sha0, AV-T Team of LisectGroup

Copyright© 2020~2025 PYAS Security By 87owo
