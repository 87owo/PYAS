# PYAS

以 Python 开发的杀毒软件，结合深度学习与行为监控来阻挡威胁！

![PYAS_UI](https://github.com/user-attachments/assets/68765836-7272-482f-b8cd-d8ba728d88ab)

## 说明语言

English : https://github.com/87owo/PYAS/blob/main/README.md

繁體中文 : https://github.com/87owo/PYAS/blob/main/README_zh_TW.md

简体中文 : https://github.com/87owo/PYAS/blob/main/README_zh_CN.md

## 安装需求

建议使用 Python 3.10。其他版本的 Python 可能需要不同的 pip 指令。

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

## 文件讯息

以下列出所有相关代码与文件的存放位置。

```
PYAS/
├── Engine/
│   ├── Models/              # ONNX 深度学习模型目录
│   └── Rules/               # YARA 与网络规则目录
│
├── Plugins/
│   └── Filter/              # 用于安全防护的 Windows 核心驱动
│
├── PYAS.py                  # 主程式与图形界面 (GUI)
├── PYAS_Config.py           # 组态处理与全域参数
├── PYAS_Engine.py           # YARA 与 ONNX 扫描引擎
├── PYAS_Interface.py        # 使用者介面定义与元件逻辑
├── PYAS_Resource.py         # 静态图片资源管理
├── PYAS_Version.py          # 打包与版本资讯
└── ...                      # 其他补充文件夹与文件
```

## 安装版本

打包发行版下载：https://github.com/87owo/PYAS/releases

## 系统需求

| 配置需求 | 权限需求    | 系统需求        | 可用內存 | 可用储存空间 |
| ---- | ------- | ----------- | ----- | ------ |
| 最低 | 系统管理员 | Windows 8.1 | 200MB | 100MB  |
| 建议 | 系统管理员 | Windows 10  | 300MB | 200MB  |
| 最佳 | 系统管理员 | Windows 11  | 500MB | 200MB  |

## 官方网站

官方网站 : https://pyantivirus.wixsite.com/pyas

开源网站 : https://github.com/87owo/PYAS

## 授权条款

https://github.com/87owo/PYAS/blob/main/LICENSE.md
