# PYAS

使用 Python 和 C 编写的杀毒软件，并通过深度学习和行为监控阻止威胁！

<img width="2245" height="1477" alt="PYAS_UI" src="https://github.com/user-attachments/assets/87d40261-7655-49ad-a19c-1ffcca60584f" />

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
│   ├── Models/
│   │   ├── convert.py               # 将可执行文件或其他文件转换为图片
│   │   └── train.py                 # TensorFlow CNN 模型训练完整代码
│   │
│   └── Rules/
│       ├── rules.yar                # YARA 病毒特征码规则匹配
│       └── rules.ips                # IP 网络地址规则匹配
│
├── Plugins/
│   └── Filter/
│       ├── DriverEntry.c            # 驱动主入口与初始化逻辑
│       ├── DriverEntry.h            # 全局驱动定义、常量与函数
│       ├── DriverPipe.c             # 内核与用户层的管道日志传输实现
│       ├── ProtectBoot.c            # 磁盘引导区写入保护
│       ├── ProtectImage.c           # 映像加载监控与 shellcode 检测
│       ├── ProtectInject.c          # 进程与线程控制，防止注入
│       ├── ProtectReg.c             # 注册表修改保护
│       ├── ProtectRules.c           # 白名单、阻止名单与文件/注册表匹配逻辑
│       └── ProtectRules.h           # 保护规则声明
│
├── PYAS.py                          # 主应用程序入口点与 UI 到引擎的接口
├── PYAS_Config.py                   # 配置加载、保存与全局参数
├── PYAS_Engine.py                   # 核心扫描引擎：YARA、IP、ONNX 模型执行
├── PYAS_Interface.py                # 用户界面组件与事件处理
├── PYAS_Resource.py                 # 静态图片与图标资源管理
├── PYAS_Version.py                  # 版本元数据，用于打包与更新
└── ...                              # 其他补充文件夹与文件
```

## 安装版本

打包发行版下载：https://github.com/87owo/PYAS/releases

## 系统需求

| 配置要求 | 权限 | 系统版本 | 处理器 | 可用内存空间 | 可用存储空间 |
| ------- | ----- | ------ | ----- | ------------ | ---------- |
| 最低配置 | 管理员 | >= Windows 10 (20H1) | 1 GHz | 200MB | 100MB |
| 推荐配置 | 管理员 | >= Windows 10 (21H2) | 3 GHz | 300MB | 200MB |

## 官方网站

官方网站 : https://pyantivirus.wixsite.com/pyas

开源网站 : https://github.com/87owo/PYAS

## 授权条款

https://github.com/87owo/PYAS/blob/main/LICENSE.txt
