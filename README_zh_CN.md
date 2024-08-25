# PYAS (Python 杀毒软件)

![PYAS](https://github.com/user-attachments/assets/39c273b9-c467-480a-a8b3-31714a6df3ef)

## 安装要求

```
psutil==5.9.5
pefile==2023.2.7
requests==2.31.0
pyperclip==1.8.2
pywin32==306
PyQt5==5.15.9
```

## 文件信息

```
PYAS/
├── Driver/
│   ├── PYAS_Driver.sys -------> 驱动程序 (0sha0 为 pyas 提供的自我保护驱动程序)
│   └── ...
│
├── Model/
│   ├── PYAS_Model.json -------> 病毒数据库 (数据库必须位于指定目录中)
│   └── ...
│
├── Rules/
│   ├── Yara_Rules.yar ---------> Yara 规则 (纯文本格式的 yara 规则)
│   ├── Yara_Rules.yrc ---------> 编译规则 (编译格式的 yara 规则)
│   └── ...
│
├── PYAS.py ---------------------> PYAS主程序（包含动画、扫描、保护等功能...）
├── PYAS_Engine.py -------------> 转换数据库（用于转换剖面图和预报数据）
├── PYAS_Suffixes.py -----------> 文件后缀（包含扫描文件后缀和常用后缀）
├── PYAS_Interface.py ----------> PyQt5界面（使用QT设计器，需与主程序搭配使用）
├── PYAS_Resource.py -----------> PyQt5资源（状态图片、图标包、按钮图标...）
├── PYAS_Language.py -----------> 翻译词典（繁体中文、简体中文、英文）
├── PYAS_Version.py ------------> 安裝信息（文件信息、版本信息、原名...）
└── ...
```

## 官方网页

https://pyantivirus.wixsite.com/pyas

https://github.com/87owo/PYAS

## 微软运行库

https://github.com/87owo/Microsoft_Runtime/releases

## 驱动程序

https://github.com/0sha0/PYAS_Protection

## 开源协议

https://github.com/87owo/PYAS/blob/main/LICENSE.md

## 支援系统

Windows 8.1, 10, 11 (64-bit), 内存 500MB, 存储 200MB 或更高

其他系统或版本可能会遇到软体功能故障或程序崩溃

## 特别感谢

360, Wix, VirusShare, mtkiao129, AV-T Team of LisectGroup

Copyright© 2020~2024 PYAS Security By 87owo
