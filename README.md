# PYAS (Python Antivirus Software)

![PYAS](https://github.com/87owo/PYAS/assets/85057800/8136aaca-d388-4321-bedb-abc4fcecfa8b)

## Readme Language

[繁體中文](https://github.com/87owo/PYAS/blob/main/README_zh_TW.md) , 
[简体中文](https://github.com/87owo/PYAS/blob/main/README_zh_CN.md)

## File Information

PYAS.py -> Main PYAS Program (including animation, scanning, protection functions, etc.)

PYAS_Engine.py -> Conversion Database (used to convert database dict and list to and from each other)

PYAS_Suffixes.py -> File Suffixes (including scanned file suffixes and common file suffixes)

PYAS_Extension.py -> Extension Kit (Extension scanners developed by other developers)

PYAS_Model.* -> Virus Database (the virus database must be placed in the same directory)

PYAS_Interface.py -> PyQt5 Interface (designed by QT designer, must be matched with the main program)

PYAS_Resource.py -> PyQt5 Resource (status pictures, icon packages, button icons, etc.)

PYAS_Language.py -> Translate Dict (Traditional Chinese, Simplified Chinese, English)

PYAS_Version.py -> Pyinstaller Info (file information, version information, original name, etc.)

## Dir Information

```
PYAS/
├── Driver/
│   ├── PYAS_Driver.sys
│   └── ...
│
├── Exten/
│   ├── bitdefender/...
│   ├── pe_sieve/...
│   └── ...
│
├── Model/
│   ├── PYAS_Model.json
│   ├── PYAS_Model.txt
│   └── ...
│
├── Rules/
│   ├── Yara_Rules.yar
│   ├── Compile_Rules.yrc
│   └── ...
│
├── PYAS.py
├── PYAS_Engine.py
└── ...
```

## Requirements

Use pip install requirements to install import module

```
psutil==5.9.5
pefile==2023.2.7
requests==2.31.0
pyperclip==1.8.2
pywin32==306
PyQt5==5.15.9
```

## Extension Kit

https://github.com/hasherezade/hollows_hunter/releases

https://github.com/hasherezade/pe-sieve/releases

https://github.com/87owo/bdc/tree/main/bitdefender

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
