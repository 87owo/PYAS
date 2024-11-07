# PYAS (Python Antivirus Software)

![PYAS](https://github.com/user-attachments/assets/39c273b9-c467-480a-a8b3-31714a6df3ef)

## Readme Language

繁體中文 : https://github.com/87owo/PYAS/blob/main/README_zh_TW.md

简体中文 : https://github.com/87owo/PYAS/blob/main/README_zh_CN.md

## Requirements

```
pip install pefile==2023.2.7
pip install pyperclip==1.8.2
pip install PyQt5==5.15.9
pip install yara-python==4.5.1
pip install numpy==2.1.1
pip install onnxruntime==1.18.1
pip install pillow==10.4.0
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

Copyright© 2020~2024 PYAS Security By 87owo
