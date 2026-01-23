# PYAS

Antivirus software written in Python and C++ that blocks threats through deep learning and behavioral monitoring!

<img width="2245" height="1477" alt="PYAS_UI" src="https://github.com/user-attachments/assets/87d40261-7655-49ad-a19c-1ffcca60584f" />

## Requirements

Python 3.10 is recommended. Other Python versions may require different pip commands.

```
pip install requests==2.32.4
pip install PySide6==6.9.1
pip install yara-python==4.5.4
pip install Pillow==11.0.0
pip install numpy==1.26.4
pip install tensorflow==2.10.0
pip install tf2onnx==1.13.0
pip install lightgbm==4.6.0
pip install onnxruntime==1.18.1
```

## File Information

The following lists the storage locations of all relevant code and other related documents.

```
PYAS/
├── Engine/
│   ├── Pattern/
│   │   ├── convert.py               # Convert executable files or other files to images
│   │   ├── train.py                 # TensorFlow CNN model training complete code
│   │   └── ...                      # Other models folders and files
│   │
│   ├── Heuristic/
│   │   ├── rules.yar                # Yara virus signature rule matching
│   │   └── ...                      # Other rules folders and files
│   └── ...                          # Other engine folders and files
│
├── Plugins/
│   └── Filter/
│   │   ├── DriverEntry.cpp          # Main driver entry and initialization logic
│   │   ├── DriverCommon.h           # Global driver definitions, constants, and functions
│   │   └── ...                      # Other driver folders and files
│   │
│   └── Rules/
│       └── rules.json               # White, block list, and matching logic for files registry
|
├── PYAS.py                          # Main application entry point and UI to engine interface
├── PYAS_Config.py                   # Configuration loading, saving, and global parameters
├── PYAS_Engine.py                   # Core scanning engine: YARA, IP, ONNX model execution
├── PYAS_Interface.py                # User interface components and event handling
├── PYAS_Resource.py                 # Static image and icon resource management
├── PYAS_Version.py                  # Version metadata for packaging and updates
└── ...                              # Other supplementary folders and files
```

## Architecture diagram

PYAS Security antivirus software general architecture diagram.

```mermaid
graph TD
    %% Global Styles
    classDef userMode fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#0d47a1
    classDef kernelMode fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#e65100
    classDef storage fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#4a148c
    classDef interaction fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,stroke-dasharray: 5 5,color:#1b5e20

    subgraph UserSpace [User Mode Application - PYAS.exe]
        direction TB
        
        GUI[MainWindow_Controller / UI]:::userMode
        ConfigMgr[Configuration & Rule Manager]:::userMode
        
        subgraph DetectionEngine [Analysis Engine - PYAS_Engine.py]
            direction TB
            SignScanner[Digital Signature Scanner]:::userMode
            PEScanner[PE Feature & Entropy Analysis]:::userMode
            YaraScanner[Heuristic / YARA Scanner]:::userMode
            CNNScanner[AI / CNN Model Scanner]:::userMode
            CloudScanner[Cloud API / Hash Check]:::userMode
        end

        subgraph UserMonitors [User-Mode Protection Threads]
            direction TB
            ProcMon[Process Monitor - CreateToolhelp32Snapshot]:::userMode
            FileMon[File Monitor - ReadDirectoryChangesW]:::userMode
            NetMon[Network Monitor - GetExtendedTcpTable]:::userMode
            SysRep[System Repair - MBR/Reg/Wallpaper]:::userMode
            PopupBlock[Popup Blocker - EnumWindows]:::userMode
            PipeClient[IPC Client Thread]:::userMode
        end

        GUI --> ConfigMgr
        GUI --> DetectionEngine
        GUI --> UserMonitors
        UserMonitors --> DetectionEngine
    end

    subgraph StorageLayer [File System / Configuration]
        direction LR
        JSONRules[JSON Rules Files]:::storage
        ConfigJSON[Config.json]:::storage
        Quarantine[Quarantine Folder]:::storage
    end

    subgraph KernelSpace [Kernel Mode Driver - PYAS_Driver.sys]
        direction TB
        
        DriverEntry[DriverEntry / Initialization]:::kernelMode
        GlobalData[Global Data & State]:::kernelMode
        CommServer[Communication Port Server]:::kernelMode

        subgraph KernelLogic [Core Protection Logic]
            RuleLoader[Rule Loader & Parser]:::kernelMode
            TrustCache[Trust Cache & Ransom Tracker]:::kernelMode
            
            subgraph MiniFilter [File System MiniFilter]
                PreCreate[PreCreate: HoneyToken / Access Control]:::kernelMode
                PreWrite[PreWrite: Ransomware / Entropy Check]:::kernelMode
                PreSetInfo[PreSetInfo: Anti-Rename / Extension]:::kernelMode
                PreDevCtrl[PreDeviceControl: Boot / Disk Wipe Protect]:::kernelMode
            end

            subgraph ObjectCallbacks [Object Manager Callbacks]
                ProcProtect[ObRegisterCallbacks: Handle Stripping]:::kernelMode
                ImageLoad[PsSetLoadImageNotifyRoutine: Image Blocking]:::kernelMode
            end

            subgraph RegistryCallbacks [Configuration Manager Callbacks]
                RegFilter[CmRegisterCallbackEx: Registry Guard]:::kernelMode
            end
        end

        DriverEntry --> GlobalData
        DriverEntry --> CommServer
        DriverEntry --> MiniFilter
        DriverEntry --> ProcProtect
        DriverEntry --> ImageLoad
        DriverEntry --> RegFilter
        
        MiniFilter --> RuleLoader
        ProcProtect --> RuleLoader
        RegFilter --> RuleLoader
        
        PreWrite --> TrustCache
        PreCreate --> TrustCache
    end

    %% Cross-Boundary Interactions
    ConfigMgr -- Writes --> JSONRules
    ConfigMgr -- Writes --> ConfigJSON
    RuleLoader -- Reads --> JSONRules
    
    GUI -- Service Control (SCM) --> DriverEntry
    PipeClient -- FltSendMessage (IPC) --> CommServer
    CommServer -- Notifications --> PipeClient
    
    FileMon -- Moves Malicious Files --> Quarantine
    
    %% Logic Flow Details
    ProcProtect -- Protects --> UserSpace
    RegFilter -- Protects --> StorageLayer
    PreDevCtrl -- Protects --> StorageLayer
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

Online Analyze : https://pyas-security.com/analyze

## Project License

For any questions, needs, or bug feedback, please contact us through the following website.

Source Issues : https://github.com/87owo/PYAS/issues

Official Email : mailto:service.pyas@gmail.com
