# PYAS (Python Antivirus Software)

![PYAS](https://github.com/87owo/PYAS/assets/85057800/8136aaca-d388-4321-bedb-abc4fcecfa8b)

## Readme Language

繁體中文 : https://github.com/87owo/PYAS/blob/main/README_zh_TW.md

简体中文 : https://github.com/87owo/PYAS/blob/main/README_zh_CN.md

## Requirements

```
psutil==5.9.5
pefile==2023.2.7
requests==2.31.0
pyperclip==1.8.2
pywin32==306
PyQt5==5.15.9
```

## File Information

```
PYAS/
├── Driver/
│   ├── PYAS_Driver.sys -------> Extension Kit (self protection driver for pyas by 0sha0)
│   └── ...
│
├── Exten/
│   ├── bitdefender/ ----------> Extension Kit (bitdefender windows console scan engine)
│   ├── pe_sieve/ -------------> Extension Kit (pe sieve windows console memory engine)
│   └── ...
│
├── Model/
│   ├── PYAS_Model.json -------> Virus Database (the database must be in the specified dir)
│   └── ...
│
├── Rules/
│   ├── Yara_Rules.yar ---------> Yara Rules (yara rules in plain text format)
│   ├── Yara_Rules.yrc ---------> Compile Rules (yara rules in compiled format)
│   └── ...
│
├── PYAS.* ---------------------> Main PYAS Program (including animation, scan, protect functions, ...)
├── PYAS_Engine.py -------------> Conversion Database (used to transform profiles and forecast data)
├── PYAS_Suffixes.py -----------> File Suffixes (including scanned file suffixes and common suffixes)
├── PYAS_Extension.py ----------> Extension Kit (extension scanners developed by other developers)
├── PYAS_Interface.py ----------> PyQt5 Interface (use QT designer, must be matched with the main program)
├── PYAS_Resource.py -----------> PyQt5 Resource (status pictures, icon packages, button icons, ...)
├── PYAS_Language.py -----------> Translate Dict (Traditional Chinese, Simplified Chinese, English)
├── PYAS_Version.py ------------> Pyinstaller (file information, version information, original name, ...)
└── ...
```

## Official Website

https://pyantivirus.wixsite.com/pyas

https://github.com/87owo/PYAS

## PYAS Driver

https://github.com/0sha0/PYAS_Protection

## MIT license

https://github.com/87owo/PYAS/blob/main/LICENSE.md

## Support System

Windows 8.1, 10, 11 (64-bit), Ram 500MB, Rom 200MB or higher

Other systems may experience software malfunctions or crash

## Special Thanks

Wix, 0sha0, mtkiao129, AV-T Team of LisectGroup

Copyright© 2020~2024 PYAS Security By 87owo
