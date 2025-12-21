# PYAS

Antivirus software written in Python and C that blocks threats through deep learning and behavioral monitoring!

<img width="2245" height="1477" alt="PYAS_UI" src="https://github.com/user-attachments/assets/87d40261-7655-49ad-a19c-1ffcca60584f" />

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
│   ├── Models/
│   │   ├── convert.py               # Convert executable files or other files to images
│   │   └── train.py                 # TensorFlow CNN model training complete code
│   │
│   └── Rules/
│       ├── rules.yar                # Yara virus signature rule matching
│       └── rules.ips                # IP network address rule matching
│
├── Plugins/
│   └── Filter/
│       ├── DriverEntry.c            # Main driver entry and initialization logic
│       ├── DriverEntry.h            # Global driver definitions, constants, and functions
│       ├── DriverPipe.c             # Kernel to user pipe logging implementation
│       ├── ProtectBoot.c            # Disk boot sector write protection
│       ├── ProtectImage.c           # Image load monitoring and shellcode detection
│       ├── ProtectInject.c          # Process thread handle access control to prevent injection
│       ├── ProtectReg.c             # Registry modification protection
│       ├── ProtectRules.c           # White, block list, and matching logic for files registry
│       └── ProtectRules.h           # Protection rule declarations
│
├── PYAS.py                          # Main application entry point and UI to engine interface
├── PYAS_Config.py                   # Configuration loading, saving, and global parameters
├── PYAS_Engine.py                   # Core scanning engine: YARA, IP, ONNX model execution
├── PYAS_Interface.py                # User interface components and event handling
├── PYAS_Resource.py                 # Static image and icon resource management
├── PYAS_Version.py                  # Version metadata for packaging and updates
└── ...                              # Other supplementary folders and files
```

## Support System

| Config    | Permissions   | System version       | Processor | Memory | Storage |
|-----------|---------------|----------------------|-----------|--------|---------|
| Minimum   | Administrator | >= Windows 10 (20H1) | 1 GHz     | 200MB  | 100MB   |
| Recommend | Administrator | >= Windows 10 (21H2) | 3 GHz     | 500MB  | 200MB   |

## Packaged Releases

Download the installer. If it is incompatible with your system, you can repackage it yourself.

Packaged Download: https://github.com/87owo/PYAS/releases

## Official Website

If you are interested in this project, you can visit the website to see other related content.

Source Available : https://github.com/87owo/PYAS

Official Website : https://pyas-security.com/antivirus

## Project License

For any questions, needs, or bug feedback, please contact us through the following website.

Source Issues : https://github.com/87owo/PYAS/issues

Official Email : mailto:service.pyas@gmail.com
