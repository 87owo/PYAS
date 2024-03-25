pyasrule_dict = {
    "A": {                                       # 規則項目名稱 Rules_1
        "abouts": {
            "author": "PYAS Security",           # 作者 PYAS Security
            "version": "1.0.0",                  # 版本 1.0.0
            "label": "Trojan",                   # 類別資訊
            "description": "Malware pattern"},   # 說明 Malware pattern
        "strings": {
            1: "physicaldrive0",                 # 所有包含匹配字串 1
            2: "512",                            # 所有包含匹配字串 2
            3: "MBR",                            # 所有包含匹配字串 3
            4: "x55",                            # 所有包含匹配字串 4
            5: "pyi-runtime-tmpdir"},            # 所有包含匹配字串 5
        "settings": {
            "count": 4,                          # 最低匹配數量 4
            "nocase": True,                      # 不分大寫小寫 True
            "types": [".exe", ".dll", ".sys"]},  # 匹配文件類別 .
        "matchs": {
            "match1": list(range(1, 5)),         # 局部匹配範圍 1 (1~4)
            "match2": list(range(2, 6))}},       # 局部匹配範圍 2 (2~5)

    "B": {
        "abouts": {
            "author": "PYAS Security",
            "version": "1.0.0",
            "label": "Trojan",
            "description": "Malware pattern"},
        "strings": {
            1: "%0|%0",
            2: "ExclusionPath",
            3: "cmdkey",
            4: "eiculwo"},
        "settings": {
            "count": 1,
            "nocase": True,
            "types": [".bat", ".cmd", ".ps1", ".js", ".vbs"]},
        "matchs": {
            "match1": list(range(1, 5))}},

    "C": {
        "abouts": {
            "author": "PYAS Security",
            "version": "1.0.0",
            "label": "Trojan",
            "description": "Malware pattern"},
        "strings": {
            1: "ProcessHacker",
            2: "MpCmdRun",
            3: "ConfigSecurityPolicy",
            4: "Client",
            5: "procexp",
            6: "MSASCui",
            7: "MsMpEng",
            8: "MpUXSrv",
            9: "CloseMutex",
            10: "NisSrv",
            11: "Regedit",
            12: "PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY",
            13: "dwProcessHandle",
            14: "Anti_Process",
            15: "MutexControl",
            16: "MSConfig"},
        "settings": {
            "count": 6,
            "nocase": True,
            "types": [".exe", ".dll", ".sys"]},
        "matchs": {
            "match1": list(range(1, 17))}},

    "D": {
        "abouts": {
            "author": "PYAS Security",
            "version": "1.0.0",
            "label": "Trojan",
            "description": "Malware pattern"},
        "strings": {
            1: "shell\\open",
            2: "exefile",
            3: "batfile",
            4: "comfile",
            5: "regfile",
            6: "mscfile",
            7: "cmdfile",
            8: "Image File Execution Options",
            9: "CurrentVersion"},
        "settings": {
            "count": 3,
            "nocase": True,
            "types": [".exe", ".dll", ".sys"]},
        "matchs": {
            "match1": list(range(1, 10))}},

    "E": {
        "abouts": {
            "author": "PYAS Security",
            "version": "1.0.0",
            "label": "Trojan",
            "description": "Malware pattern"},
        "strings": {
            1: "kill",
            2: "PYAS",
            3: "lsass",
            4: "csrss",
            5: "smss",
            6: "taskmgr",
            7: "svchost"},
        "settings": {
            "count": 3,
            "nocase": True,
            "types": [".exe", ".dll", ".sys"]},
        "matchs": {
            "match1": list(range(1, 8))}},

    "F": {
        "abouts": {
            "author": "PYAS Security",
            "version": "1.0.0",
            "label": "Trojan",
            "description": "Malware pattern"},
        "strings": {
            1: "NoControlPanel",
            2: "NoFileMenu",
            3: "NoFind",
            4: "NoRealMode",
            5: "NoRecentDocsMenu",
            6: "NoSetFolders",
            7: "NoSetFolderOptions",
            8: "NoViewOnDrive",
            9: "NoDesktop",
            10: "NoAddingComponents",
            11: "NoLogOff",
            12: "NoFolderOptions",
            13: "DisableCMD",
            14: "NoViewContexMenu",
            15: "HideClock",
            16: "Wallpaper",
            17: "NoStartMenuMorePrograms",
            18: "NoStartMenuMyGames",
            19: "NoStartMenuMyMusic",
            20: "NoStartMenuNetworkPlaces",
            21: "NoStartMenuPinnedList",
            22: "NoActiveDesktop",
            23: "NoSetActiveDesktop",
            24: "NoActiveDesktopChanges",
            25: "NoChangeStartMenu",
            26: "ClearRecentDocsOnExit",
            27: "NoFavoritesMenu",
            28: "DisableLockWorkstation",
            29: "NoSetTaskbar",
            30: "NoSMHelp",
            31: "NoTrayContextMenu",
            32: "NoViewContextMenu",
            33: "NoWindowsUpdate",
            34: "NoComponents",
            35: "NoWinKeys",
            36: "StartMenuLogOff",
            37: "NoSimpleNetlDList",
            38: "NoLowDiskSpaceChecks",
            39: "Restrict_Run",
            40: "NoManageMyComputerVerb",
            41: "DisableTaskMgr",
            42: "DisableRegistryTools",
            43: "DisableChangePassword"},
        "settings": {
            "count": 2,
            "nocase": True,
            "types": [".exe", ".dll", ".sys"]},
        "matchs": {
            "match1": list(range(1, 44))}},

    "G": {
        "abouts": {
            "author": "PYAS Security",
            "version": "1.0.0",
            "label": "Ransom",
            "description": "Malware pattern"},
        "strings": {
            1: "certutil",
            2: "encode",
            3: "decode",
            4: "random"},
        "settings": {
            "count": 4,
            "nocase": True,
            "types": [".bat", ".cmd", ".ps1", ".js", ".vbs"]},
        "matchs": {
            "match1": list(range(1, 5))}},

    "H": {
        "abouts": {
            "author": "PYAS Security",
            "version": "1.0.0",
            "label": "Trojan",
            "description": "Malware pattern"},
        "strings": {
            1: "%userprofile%",
            2: "C:\\Windows",
            3: "%SYSTEMROOT%",
            4: "%WINDIR%",
            5: "%SYSTEMDRIVE%",
            6: "%TEMP%",
            7: "%TMP%",
            8: "del"},
        "settings": {
            "count": 4,
            "nocase": True,
            "types": [".bat", ".cmd", ".ps1", ".js", ".vbs"]},
        "matchs": {
            "match1": list(range(1, 9))}},

}
