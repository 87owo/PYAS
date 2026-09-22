# PYAS Security

<div align="center">

**A hybrid Windows endpoint security platform powered by machine learning, YARA rules, cloud analysis, and kernel-level behavioral protection.**

[![Latest Release](https://img.shields.io/github/v/release/87owo/PYAS?display_name=tag&style=flat-square)](https://github.com/87owo/PYAS/releases/latest)
[![GitHub Stars](https://img.shields.io/github/stars/87owo/PYAS?style=flat-square)](https://github.com/87owo/PYAS/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/87owo/PYAS?style=flat-square)](https://github.com/87owo/PYAS/network/members)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4?style=flat-square&logo=windows)](https://github.com/87owo/PYAS)
[![Python](https://img.shields.io/badge/Python-3.10-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![C++](https://img.shields.io/badge/kernel-C%2B%2B-00599C?style=flat-square&logo=cplusplus)](https://github.com/87owo/PYAS/tree/main/Plugins/Filter/PYAS_Driver)

[Website](https://pyas-security.com/antivirus) · [Online Analysis](https://pyas-security.com/analyze) · [Download](https://github.com/87owo/PYAS/releases) · [Report an Issue](https://github.com/87owo/PYAS/issues)

</div>

![PYAS Security interface](https://github.com/user-attachments/assets/1991aad3-64cc-4266-ac67-dab70c891ce7)

## Overview

PYAS Security is a source-available Windows endpoint security project that combines multiple detection and protection layers in one desktop application. It brings together local PE-file machine-learning inference, YARA-based matching, digital-signature inspection, optional cloud analysis, real-time user-mode monitoring, and a native Windows minifilter driver.

The project is designed both as a usable security application and as an engineering platform for studying malware detection, Windows internals, rule-driven prevention, model training, and online file analysis.

> [!IMPORTANT]
> PYAS is an independent security project. No antivirus product can guarantee detection of every threat. Evaluate it in a controlled environment before production use, keep backups, and review alerts before deleting files.

## Why PYAS

- **Layered detection** — combines YARA, PE feature analysis, ONNX models, signature verification, and cloud-assisted analysis.
- **Behavior-oriented protection** — monitors processes, files, memory, network activity, system settings, and sensitive operations.
- **Kernel integration** — includes a C++ minifilter driver with configurable protection rules and user-mode communication.
- **Local-first scanning** — performs core static analysis on the endpoint; cloud submission is separately configurable.
- **Operational tooling** — adds quarantine, allow/block lists, system repair, startup management, cleanup, and activity reporting.
- **Research-ready codebase** — includes model-training utilities, an online analysis service, an API client, experimental engines, and a visual rule editor.

## Protection capabilities

| Layer | Capability | Implementation |
|---|---|---|
| Static rules | File and process-memory matching | YARA rules compiled and loaded by `rule_scanner` |
| PE machine learning | Feature extraction and local classification | `pefile`, NumPy, ONNX Runtime |
| Signature trust | Authenticode verification | Windows WinVerifyTrust APIs |
| Cloud analysis | Upload, polling, rescan, and result retrieval | HTTPS API with chunked upload support |
| Process protection | New-process inspection, optional suspension, termination controls | Win32/NT APIs and worker pools |
| File protection | Directory change monitoring, debounced real-time scans, file locking | Windows file notification APIs |
| Memory protection | Process-memory YARA scanning and kernel callbacks | User-mode scanner plus driver rules |
| Network visibility | Process-aware TCP connection monitoring | Windows IP Helper APIs |
| Kernel enforcement | File, process/thread, registry, memory, image-load, and boot/disk controls | Native C++ minifilter driver |
| Recovery and maintenance | Quarantine, system repair, startup management, cleanup, MBR backup/check | Python application services |

Protection modules are individually configurable. Several active-protection switches are disabled by default so users can enable only the controls appropriate for their environment.

## Detection pipeline

```mermaid
flowchart LR
    A[File or process event] --> B{Scope and policy checks}
    B -->|Allowed| C[Hash and metadata]
    B -->|Excluded| Z[Skip]
    C --> D[Digital signature verification]
    C --> E[YARA rule scan]
    C --> F[PE feature extraction]
    F --> G[ONNX model inference]
    D --> H[Local verdict aggregation]
    E --> H
    G --> H
    H --> I{Cloud analysis enabled?}
    I -->|Yes| J[Hash lookup / chunked upload]
    J --> K[Cloud report]
    I -->|No| L[Local result]
    K --> M[Alert and response]
    L --> M
    M --> N[Quarantine / delete / allow]
```

## System architecture

```mermaid
flowchart TB
    subgraph UI[Presentation layer]
        WEB[HTML / CSS / JavaScript]
        WV[WebView2 desktop shell]
        TRAY[System tray and Windows shell integration]
    end

    subgraph APP[Python application layer]
        CORE[PYAS.py orchestration]
        SCAN[ScannerMixin]
        PROTECT[ProtectMixin]
        TOOLS[ToolsMixin]
        ENGINE[PYAS_Engine.py]
    end

    subgraph DETECT[Detection engines]
        YARA[YARA rules]
        PE[PE feature extractor]
        ONNX[ONNX Runtime models]
        SIGN[Authenticode verification]
        CLOUD[PYAS Cloud API]
    end

    subgraph KERNEL[Windows kernel layer]
        PORT[Filter Manager communication port]
        RULES[Dynamic rule engine and trust cache]
        FILE[File-system minifilter]
        PROC[Process and thread callbacks]
        REG[Registry callbacks]
        MEM[Memory and image-load controls]
        BOOT[Boot and disk I/O controls]
    end

    subgraph ONLINE[Online analysis platform]
        API[Flask application and REST API]
        QUEUE[Priority analysis workers]
        DB[(PostgreSQL)]
        STORAGE[(Sample and report storage)]
    end

    WEB <--> WV
    WV <--> CORE
    TRAY <--> CORE
    CORE --> SCAN
    CORE --> PROTECT
    CORE --> TOOLS
    SCAN --> ENGINE
    PROTECT --> ENGINE
    ENGINE --> YARA
    ENGINE --> PE
    PE --> ONNX
    ENGINE --> SIGN
    ENGINE -. optional HTTPS .-> CLOUD
    PROTECT <--> PORT
    PORT <--> RULES
    RULES --> FILE
    RULES --> PROC
    RULES --> REG
    RULES --> MEM
    RULES --> BOOT
    CLOUD --> API
    API --> QUEUE
    QUEUE --> DB
    QUEUE --> STORAGE
```

## Repository layout

```text
PYAS/
├── PYAS.py                    # Desktop entry point, UI bridge, configuration and lifecycle
├── PYAS_Engine.py             # YARA, PE/ML, signature and cloud scanning engines
├── PYAS_Scanner.py            # Scan scheduling, workers, results and remediation
├── PYAS_Protect.py            # Real-time protection and driver lifecycle/communication
├── PYAS_Tools.py              # Windows utilities, startup, process, network and cleanup tools
├── PYAS_Version.py            # Windows executable version metadata
├── Engine/
│   ├── Heuristic/             # YARA signatures and rule assets
│   └── Properties/            # PE feature models and training/inference utilities
├── Interface/                 # WebView2 HTML, CSS, JavaScript and icons
└── Plugins/
    ├── Filter/                # Native Windows minifilter driver source
    └── Rules/                 # Driver protection policies
```

## Getting started

### Option 1 — Install a packaged release

For most users, download the latest installer from [GitHub Releases](https://github.com/87owo/PYAS/releases).

1. Confirm that the installer comes from the official `87owo/PYAS` repository.
2. Ensure Microsoft Visual C++ 2015–2022 Redistributable and Microsoft Edge WebView2 Runtime are installed.
3. Run the installer as an administrator.
4. Open PYAS and review the protection switches before enabling kernel-level controls.

The current source tree may be ahead of the latest packaged release. Consult the version shown in the application and the release notes when reporting issues.

### Option 2 — Run from source

Python 3.10 is the recommended development runtime.

```powershell
git clone https://github.com/87owo/PYAS.git
cd PYAS
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install pystray pefile requests pywebview Pillow yara-python numpy onnxruntime
python PYAS.py
```

Administrator privileges are required for features that interact with protected processes, system configuration, services, physical disks, or the kernel driver. Running the desktop UI without elevation may leave those capabilities unavailable.

### Optional training dependencies

The following packages are used by model-training or data-preparation utilities and are not required for the normal desktop runtime:

```powershell
pip install pandas scikit-learn lightgbm onnxmltools orjson
```

## Runtime requirements

| Profile | Operating system | Privileges | CPU | Memory | Free storage |
|---|---|---:|---:|---:|---:|
| Minimum | Windows 10 20H1 or newer | Administrator for full protection | 1 GHz | 300 MB | 100 MB |
| Recommended | Windows 10 21H2 / Windows 11 | Administrator | 3 GHz | 500 MB+ | 200 MB+ |

Required platform components:

- Microsoft Visual C++ 2015–2022 Redistributable
- Microsoft Edge WebView2 Runtime
- 64-bit Windows for the included x64 driver build

Actual resource usage depends on the selected scan scope, file sizes, enabled models, number of active workers, and real-time protection settings.

## Command-line integration

The application supports Windows shell and maintenance workflows through command-line arguments:

```text
PYAS.exe -scan <path>          Scan a file or directory, forwarding to an existing instance
PYAS.exe -hide                Start with the main window hidden
PYAS.exe -quit                Request the running instance to exit
PYAS.exe -driver-unload       Unload the active filter driver
PYAS.exe -driver-uninstall    Stop and remove the driver service
```

These commands are primarily intended for installer, shell-menu, and maintenance integration. Administrative rights may be required.

## Configuration and local data

PYAS stores machine-wide configuration and reports under:

```text
%ProgramData%\PYAS\Config.json
%ProgramData%\PYAS\Report.json
```

WebView2 user data and its diagnostic log are stored under the current user's local application-data directory. Configuration includes scan limits, enabled protection layers, language and theme preferences, custom rule references, allow/block lists, and quarantine metadata.

Before reporting a configuration issue, reproduce it with default settings when safe to do so and remove sensitive paths or file information from logs.

## Online analysis service

The `Analyze/` component is a separate Flask and PostgreSQL application that provides:

- regular and chunked file uploads;
- asynchronous priority-based analysis tasks;
- SHA-256 report lookup and rescanning;
- structured PE metadata and similarity analysis;
- authenticated API access;
- search, statistics, comments, votes, and report export;
- encrypted sample packaging and controlled download workflows.

The service can be containerized with Docker Compose, but the checked-in deployment configuration must be treated as a development example. Replace all credentials and tokens with environment-managed secrets before deployment, restrict sample access, terminate TLS at a trusted reverse proxy, and isolate the analysis workers from production networks.

## Python API example

`Analyze/PYAS_Analyze_API.py` provides a client for the online analysis API:

```python
from Analyze.PYAS_Analyze_API import PYAS_Client

client = PYAS_Client(
    api_key="YOUR_API_KEY",
    hosts="https://pyas-security.com",
)

sha256 = client.upload_file(r"C:\samples\candidate.exe")
if sha256 and client.wait_for_analysis(sha256):
    report = client.get_report(sha256)
    print(report)
```

Only submit files that you are authorized to upload. Samples may contain confidential or personal information.

## Building the driver

The driver source is located in `Plugins/Filter/PYAS_Driver/` and includes a Visual Studio solution and project.

Typical prerequisites:

- Visual Studio with Desktop development with C++;
- a compatible Windows Driver Kit (WDK);
- an x64 build environment;
- an appropriate test-signing or production code-signing workflow.

Build and test kernel components only in an isolated virtual machine with snapshots. Windows driver loading policies apply, and production distribution requires appropriate signing. Do not disable platform security controls on a primary workstation merely to load a development build.

## Rule editor

PYAS includes a Blockly-based visual editor for creating driver protection rules. The packaged editor is distributed through project releases.

![PYAS rule editor](https://github.com/user-attachments/assets/29a816a8-3bf9-4e1c-b881-7336676ad7f9)

Driver rules support matching across categories such as file, process, thread, registry, memory, device, and image-load activity, with allow/deny behavior, priority, operation masks, path relationships, thresholds, and other contextual constraints.

## Machine-learning engine

The local PE engine extracts structural and statistical characteristics from Windows executables, including headers, sections, data directories, imports, exports, resources, strings, byte distributions, entropy windows, overlay data, Rich headers, load configuration, certificates, and entry-point anomalies. Features are ordered according to the model metadata and evaluated through ONNX Runtime.

![Model training result](https://github.com/user-attachments/assets/fa7cf0e2-01a1-4234-9358-718c2b8a2c9a)

Model performance shown by training output should not be interpreted as a universal real-world detection rate. Reproducible evaluation requires a documented dataset split, class balance, deduplication strategy, temporal holdout, false-positive analysis, and testing against previously unseen malware families.

## Development and verification

Run the Windows-focused unit tests with:

```powershell
python -m unittest discover -s tests -v
```

Before submitting a change:

1. Keep modifications scoped to the affected protection layer.
2. Test both successful and denied Windows API paths.
3. Verify cleanup of handles, services, threads, temporary files, and driver ports.
4. Exercise the UI flow in both English and Traditional Chinese.
5. Test driver changes in a disposable VM, including unload and recovery behavior.
6. Record the Windows build, Python version, driver-signing mode, and enabled switches.

## Security and privacy

- Cloud scanning is optional; review the active configuration before analyzing confidential files.
- Kernel drivers and remediation features can affect system stability and data availability.
- Quarantine, deletion, startup changes, system repair, and MBR operations should be tested with recoverable data.
- Never deploy the example online-analysis stack with repository-default credentials or tokens.
- Treat uploaded malware samples as hostile. Use isolated storage, least privilege, network segmentation, and strict download authorization.
- If you discover a vulnerability, avoid publishing exploit details before the maintainer has had a reasonable opportunity to respond.

## Project status

PYAS is actively developed. The source tree can contain features intended for a future release, experimental modules, generated artifacts, and research data that are not part of the stable desktop package. For end-user installation, prefer signed artifacts from [Releases](https://github.com/87owo/PYAS/releases); for development, pin dependencies and validate the exact revision you build.

## Contributing

Issues and focused pull requests are welcome.

- Search [existing issues](https://github.com/87owo/PYAS/issues) before opening a new report.
- Include reproducible steps, expected and actual behavior, logs with sensitive data removed, and environment details.
- Keep unrelated refactors out of bug-fix pull requests.
- Do not commit malware samples, credentials, tokens, private certificates, or machine-specific build output.

## License and third-party components

The repository contains component-specific license files and bundled third-party assets. GitHub does not currently identify a repository-wide SPDX license. Review the applicable license files and obtain clarification from the maintainer before redistribution, commercial use, or incorporation into another product.

## Links and contact

- Source: [github.com/87owo/PYAS](https://github.com/87owo/PYAS)
- Releases: [github.com/87owo/PYAS/releases](https://github.com/87owo/PYAS/releases)
- Official website: [pyas-security.com/antivirus](https://pyas-security.com/antivirus)
- Online analysis: [pyas-security.com/analyze](https://pyas-security.com/analyze)
- Issue tracker: [github.com/87owo/PYAS/issues](https://github.com/87owo/PYAS/issues)
- Email: [service@pyas-security.com](mailto:service@pyas-security.com)

---

<div align="center">

Built for Windows security research, layered endpoint defense, and transparent experimentation.

</div>
