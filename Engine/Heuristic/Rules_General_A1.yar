import "pe"

private rule General_WinPE_AnySizePE
{
    condition:
        filesize >= 1KB and
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550
}

private rule General_WinPE_ValidPE
{
    condition:
        filesize >= 1KB and
        filesize < 50MB and
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550
}

rule Backdoor_WinPE_CobaltStrike
{
    meta:
        description = "Cobalt Strike Beacon command and injection diagnostic string set"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "component; may occur inside loaders or coin-miner bundles"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $anchor_1 = "beacon.dll" ascii wide
        $anchor_2 = "beacon.x64.dll" ascii wide
        $feature_1 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')" ascii wide
        $feature_2 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" ascii wide
        $feature_3 = "could not create remote thread in %d: %d" ascii wide
        $feature_4 = "could not write to process memory: %d" ascii wide
        $feature_5 = "Could not connect to pipe (%s): %d" ascii wide
        $feature_6 = "Could not open process token: %d (%u)" ascii wide
        $feature_7 = "%d is an x64 process (can't inject x86 content)" ascii wide
        $feature_8 = "ppid %d is in a different desktop session" ascii wide
        $ep_8 = { E8 83 05 00 00 E9 AE FD FF FF CC CC CC CC CC CC }
        $ep_9 = { E8 63 06 00 00 E9 AE FD FF FF CC CC CC CC CC CC }
        $code_016_1 = { 15 00 00 E8 B8 FC FF FF 90 90 48 83 C4 28 C3 90 }
        $code_016_2 = { 00 E8 BA 04 00 00 E8 A5 FC FF FF 90 90 48 83 C4 }
        $code_016_3 = { D2 0F 85 6A FF FF FF 49 83 F9 FF 75 0A 43 88 5C }
        $code_032_7 = { CC CC CC CC CC 6A 18 68 E0 66 43 00 E8 23 06 00 }
        $code_032_9 = { 3B 0D 00 10 41 00 75 03 C2 00 00 E9 FA 00 00 00 }
        $code_048_1 = { 15 00 00 E8 98 FC FF FF 90 90 48 83 C4 28 C3 90 }
        $code_048_2 = { 00 00 83 C4 0C E9 96 FC FF FF 90 90 90 90 90 90 }
        $code_064_5 = { 90 54 58 48 89 58 20 4C 89 40 18 89 50 10 48 89 }
        $code_064_6 = { 75 16 FF 75 08 8B 35 08 83 43 00 8B CE FF 15 74 }
        $code_064_9 = { 00 83 65 D8 00 A1 3C 1F 41 00 89 45 E0 83 F8 FF }
        $code_064_11 = { 54 58 90 48 89 58 20 4C 89 40 18 89 50 10 48 89 }
        $code_064_12 = { 00 E8 9A FD 00 00 E8 85 FC FF FF 90 90 48 83 C4 }
        $code_080_3 = { 00 00 00 48 63 F2 49 89 CC 89 D7 4C 89 C5 48 89 }
        $code_096_1 = { 48 83 EC 28 E8 4F 19 00 00 48 85 C0 0F 94 C0 0F }
        $code_096_4 = { 8B F1 BA 01 00 00 00 89 50 B8 09 DB 75 0F 39 1D }
        $code_128_1 = { 55 57 56 53 48 83 EC 40 41 B9 04 00 00 00 48 63 }
        $code_128_3 = { 83 F8 01 77 38 48 8B 05 08 1F 01 00 48 85 C0 74 }
        $code_128_5 = { 83 F8 01 77 38 48 8B 05 08 1F 01 00 48 09 C0 74 }
        $code_144_3 = { 4C 8B 5C 24 08 48 83 C4 10 C3 CC CC 48 89 5C 24 }
        $code_144_4 = { 0A 8B D3 FF D0 8B D0 89 44 24 20 09 D2 74 17 4C }
        $code_160_7 = { 55 89 E5 8B 45 08 5D FF E0 55 89 E5 83 EC 10 8B }
        $code_176_4 = { EC 3C 8B 75 0C C7 44 24 0C 04 00 00 00 C7 44 24 }
        $code_176_11 = { 57 56 53 48 83 EC 20 31 DB 48 85 C9 48 89 CE 74 }
        $code_176_12 = { 24 20 09 C0 75 07 33 C0 E9 92 00 00 00 4C 8B C6 }
        $code_192_2 = { 8B D3 49 8B CE E8 B6 B3 FF FF 8B F8 89 44 24 20 }
        $code_192_5 = { F9 48 89 4C 24 68 4C 8B EA 4D 85 C0 74 1A 4D 85 }

        $ext_arch32 = "%d is an x86 process (can't inject x64 content)" ascii
        $ext_arch64 = "%d is an x64 process (can't inject x86 content)" ascii
        $ext_thread = "could not create remote thread in %d: %d" ascii
        $ext_memory = "could not write to process memory: %d" ascii
        $ext_pipe = "Could not connect to pipe (%s): %d" ascii
        $ext_token = "Could not open process token: %d (%u)" ascii
        $ext_command = "powershell -nop -exec bypass -EncodedCommand" ascii
    condition:
        (((General_WinPE_ValidPE and
        1 of ($anchor_*) and
        3 of ($feature_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_2 at (pe.entry_point + 16) and $code_096_1 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_048_1 at (pe.entry_point + 48) and $code_128_1 at (pe.entry_point + 128))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_080_3 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_048_2 at (pe.entry_point + 48) and $code_176_4 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_128_3 at (pe.entry_point + 128) and $code_192_2 at (pe.entry_point + 192))
                or ($code_016_3 at (pe.entry_point + 16) and $code_144_3 at (pe.entry_point + 144) and $code_192_5 at (pe.entry_point + 192))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_128_5 at (pe.entry_point + 128) and $code_192_2 at (pe.entry_point + 192))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_048_2 at (pe.entry_point + 48) and $code_160_7 at (pe.entry_point + 160))
                or ($ep_8 at (pe.entry_point + 0) and $code_032_7 at (pe.entry_point + 32) and $code_064_6 at (pe.entry_point + 64))
                or ($ep_9 at (pe.entry_point + 0) and $code_032_9 at (pe.entry_point + 32) and $code_064_9 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_064_12 at (pe.entry_point + 64) and $code_176_11 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_064_5 at (pe.entry_point + 64) and $code_144_4 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_096_4 at (pe.entry_point + 96) and $code_176_12 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_064_11 at (pe.entry_point + 64) and $code_144_4 at (pe.entry_point + 144))))) and
        (1 of ($anchor_*) and 3 of ($feature_*))) or
        (General_WinPE_AnySizePE and
        1 of ($ext_arch*) and 4 of ($ext_*) and
        pe.imports("kernel32.dll", "GetProcAddress") and
        (pe.imports("kernel32.dll", "VirtualAlloc") or pe.imports("kernel32.dll", "VirtualProtect")))
}

rule Backdoor_MSIL_DcRat
{
    meta:
        description = "DcRat-compatible .NET RAT client, TLS, mutex and persistence string set"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "component; related AsyncRAT-derived clients may share this core"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $anchor_1 = "ReadServertData" ascii wide
        $anchor_2 = "Client.Handle_Packet" ascii wide
        $anchor_3 = "Serversignature" ascii wide
        $anchor_4 = "Global\\Mutex_Unique_RAT_2026" ascii wide
        $feature_1 = "RtlSetProcessIsCritical" ascii wide
        $feature_2 = "MutexControl" ascii wide
        $feature_3 = "InitializeClient" ascii wide
        $feature_4 = "ValidateServerCertificate" ascii wide
        $feature_5 = "Client.Connection" ascii wide
        $feature_6 = "ClientSocket" ascii wide
        $feature_7 = "<SslClient>k__BackingField" ascii wide
        $feature_8 = "NormalStartup" ascii wide
        $feature_9 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" ascii wide nocase
    condition:
        ((General_WinPE_ValidPE and
        1 of ($anchor_*) and
        4 of ($feature_*))) and
        (pe.data_directories[14].size > 0 and 1 of ($anchor_1, $anchor_2, $anchor_3) and 4 of ($feature_*))
}

rule Backdoor_WinPE_Remcos
{
    meta:
        description = "Remcos RAT keylogger, clipboard, transfer and browser-data control messages"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "family cluster"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $anchor_1 = "Remcos_Mutex_Inj" ascii wide
        $anchor_2 = "rmclient.exe" ascii wide nocase
        $anchor_3 = "Uploading file to Controller:" ascii wide
        $anchor_4 = "[Chrome StoredLogins found, cleared!]" ascii wide
        $feature_1 = "Offline Keylogger Started" ascii wide
        $feature_2 = "Online Keylogger Started" ascii wide
        $feature_3 = "Keylogger initialization failure: error" ascii wide
        $feature_4 = "[End of clipboard]" ascii wide
        $feature_5 = "[Text copied to clipboard]" ascii wide
        $feature_6 = "[Text pasted from clipboard]" ascii wide
        $feature_7 = "Failed to download file:" ascii wide
        $feature_8 = "Failed to upload file:" ascii wide
        $feature_9 = "Connection Error: Unable to create socket" ascii wide
        $feature_10 = "FoxMailRecovery" ascii wide
        $feature_11 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii wide nocase
        $feature_12 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" ascii wide nocase
        $ep_1 = { E8 21 97 00 00 E9 00 00 00 00 6A 14 68 00 9E 42 }
        $ep_2 = { 55 8B EC 6A FF 68 50 41 40 00 68 70 13 40 00 64 }
        $ep_3 = { E8 77 04 00 00 E9 8E FE FF FF 55 8B EC 81 EC 24 }
        $ep_4 = { 55 8B EC 6A FF 68 18 19 41 00 68 60 FC 40 00 64 }
        $ep_5 = { E8 22 05 00 00 E9 7A FE FF FF 55 8B EC 81 EC 24 }
        $ep_7 = { E8 26 05 00 00 E9 7A FE FF FF 55 8B EC 81 EC 24 }
        $ep_10 = { 55 54 5D 6A FF 68 38 F4 40 00 68 40 DE 40 00 64 }
        $code_016_6 = { 03 00 00 53 56 6A 17 E8 E1 26 02 00 85 C0 74 05 }
        $code_032_1 = { E8 B4 96 00 00 59 B8 4D 5A 00 00 66 39 05 00 00 }
        $code_032_2 = { 53 56 57 89 65 E8 83 65 FC 00 6A 01 FF 15 58 20 }
        $code_032_3 = { 53 56 57 89 65 E8 83 65 FC 00 6A 01 FF 15 60 40 }
        $code_048_1 = { 40 40 00 59 83 0D 54 62 40 00 FF 83 0D 58 62 40 }
        $code_048_9 = { 53 41 00 59 83 0D 6C C2 41 00 FF 83 0D 70 C2 41 }
        $code_064_2 = { FF FF 15 54 20 40 00 8B 0D 2C 30 40 00 89 08 FF }
        $code_064_3 = { 00 FF FF 15 14 03 41 00 8B 0D 14 5C 41 00 89 08 }
        $code_064_5 = { FF FF 15 5C 40 40 00 8B 0D 30 50 40 00 89 08 FF }
        $code_064_8 = { 00 FF FF 15 0C E3 40 00 8B 0D 9C 3F 41 00 89 08 }
        $code_080_1 = { FF 15 54 40 40 00 8B 0D 48 62 40 00 89 08 A1 9C }
        $code_096_1 = { 76 09 39 98 E8 00 40 00 0F 95 C3 89 5D E4 E8 2E }
        $code_096_3 = { 40 00 8B 00 A3 F4 30 40 00 E8 C3 00 00 00 83 3D }
        $code_096_6 = { 40 00 8B 00 A3 64 50 40 00 E8 C3 00 00 00 83 3D }
        $code_128_3 = { 41 00 59 E8 EE 00 00 00 68 E0 A0 41 00 68 DC A0 }
        $code_128_6 = { 41 00 59 E8 EE 00 00 00 68 E8 B0 41 00 68 E4 B0 }
        $code_192_3 = { A8 56 50 E8 D9 23 00 00 8B 45 04 83 C4 0C C7 45 }
        $code_192_4 = { 68 00 A0 41 00 E8 A6 00 00 00 83 C4 24 A1 80 43 }
        $code_192_7 = { 45 A8 6A 00 50 E8 50 24 00 00 8B 45 04 83 C4 0C }
        $code_192_9 = { 45 A8 6A 00 50 E8 F4 27 00 00 8B 45 04 83 C4 0C }
        $code_192_11 = { A8 56 50 E8 CB 23 00 00 8B 45 04 83 C4 0C C7 45 }
    condition:
        ((General_WinPE_ValidPE and
        1 of ($anchor_*) and
        3 of ($feature_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_096_1 at (pe.entry_point + 96))
                or ($ep_2 at (pe.entry_point + 0) and $code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_192_3 at (pe.entry_point + 192))
                or ($code_032_2 at (pe.entry_point + 32) and $code_064_2 at (pe.entry_point + 64) and $code_096_3 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_4 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_128_3 at (pe.entry_point + 128) and $code_192_4 at (pe.entry_point + 192))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_5 at (pe.entry_point + 0) and $code_192_7 at (pe.entry_point + 192))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_7 at (pe.entry_point + 0) and $code_192_9 at (pe.entry_point + 192))
                or ($code_032_3 at (pe.entry_point + 32) and $code_064_5 at (pe.entry_point + 64) and $code_096_6 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_048_9 at (pe.entry_point + 48) and $code_128_6 at (pe.entry_point + 128))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_6 at (pe.entry_point + 16) and $code_192_11 at (pe.entry_point + 192))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_10 at (pe.entry_point + 0) and $code_064_8 at (pe.entry_point + 64))))) and
        (1 of ($anchor_*) and 1 of ($feature_1, $feature_2, $feature_3, $feature_4, $feature_5, $feature_6) and 3 of ($feature_*))
}

rule Backdoor_MSIL_NanoCore
{
    meta:
        description = "Stable obfuscated identifier cluster observed in NanoCore RAT samples"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "family cluster; may also match a dropper containing the same payload"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $id_1 = "#=qiY1B9yU2oVkPHxhn$y67SFTP8x1Jb0botGqdUGkdpQg=" ascii
        $id_2 = "#=qqnp3i0xG3gb2LwEmwQLB8NQerATuB2G0aH1k$$26lgk=" ascii
        $id_3 = "#=q85afbI_HcqBFOZnC0iAqsNghLb3LsuyjFtpLEYYoPX8=" ascii
        $id_4 = "#=q$fGRvwQxjFKeY$SH10p0pyPTU$R77VMKr3CcLFQeQ2Y=" ascii
        $id_5 = "#=q$Rh_ulnlhN$9Zn9n4fKAsvWT9cisaHT_PgvcGANnd6o=" ascii
        $id_6 = "#=q0PMcXQJxcLLr1sYO0fpyhPjUwjQtInL_vJPQSgCsfio=" ascii
        $id_7 = "#=q1A7nXYgjUuxh_0aV4fZMB87On7HuSdbeS8x$mfXfW2c=" ascii
        $id_8 = "#=q1Ld$ycQpy0q1QvYRFk1k5lwgysKVR2tJyNFjakVtbYY=" ascii
    condition:
        (General_WinPE_ValidPE and 4 of ($id_*))
}

rule TrojanSpy_MSIL_SnakeLogger
{
    meta:
        description = "Stable encoded constant cluster observed in SnakeLogger samples"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "family cluster"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $encoded_1 = "6c2093102da079209310cc9" ascii
        $encoded_2 = "1b0c9109f102930c0109f0" ascii
        $encoded_3 = "47e656d6e6f6279667e654" ascii
        $encoded_4 = "c6c646e2565627f63637d6" ascii
        $encoded_5 = "e0c260a06110b230ef4140" ascii
        $encoded_6 = "e69616d4c6c64427f634f5" ascii
        $encoded_7 = "1c0a0109b108230ca109a" ascii
        $encoded_8 = "3747e656e6f607d6f636" ascii
        $encoded_9 = "c0a9706011b2b061a0a0" ascii
        $encoded_10 = "9c105870df101a10f79" ascii
        $encoded_11 = "9e10ca303e109f10899" ascii
        $encoded_12 = "eb10e510a510b410831" ascii
    condition:
        (General_WinPE_ValidPE and 8 of ($encoded_*))
}

rule TrojanSpy_WinPE_Formbook
{
    meta:
        description = "Three co-occurring code-like strings observed in Formbook samples"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "family cluster"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_1 = "E$SQRPVW" ascii
        $code_2 = "9FBNGu.W" ascii
        $code_3 = ":FBNGu2j" ascii
        $ep_1 = { E8 17 15 00 00 E9 00 00 00 00 6A 14 68 78 A6 40 }
        $ep_4 = { E8 36 18 00 00 E9 89 FE FF FF 8B FF 55 8B EC 81 }
        $ep_5 = { 55 8B EC 83 EC 64 E8 F5 C7 FF FF 8B E5 5D C3 E8 }
        $ep_6 = { 55 8B EC 83 EC 64 E8 D5 C8 FF FF 8B E5 5D C3 E8 }
        $ep_8 = { 55 8B EC 83 EC 64 E8 95 C7 FF FF 8B E5 5D C3 E8 }
        $ep_9 = { 55 8B EC 83 EC 64 E8 35 C8 FF FF 8B E5 5D C3 E8 }
        $code_032_1 = { FF FF C3 E8 00 00 00 00 58 C3 E9 11 C9 FF FF C3 }
        $code_032_3 = { FF FF C3 E8 00 00 00 00 58 C3 E9 A1 C8 FF FF C3 }
        $code_032_4 = { FF FF C3 E8 00 00 00 00 58 C3 E9 81 C9 FF FF C3 }
        $code_032_7 = { 75 08 E8 D8 15 00 00 83 3D 24 C1 40 00 00 59 59 }
        $code_032_9 = { FF FF C3 E8 00 00 00 00 58 C3 E9 E1 C8 FF FF C3 }
        $code_048_2 = { E8 00 00 00 00 58 C3 68 88 88 88 88 E9 6F E2 FF }
        $code_048_4 = { E8 00 00 00 00 58 C3 68 88 88 88 88 E9 CF E2 FF }
        $code_048_5 = { E8 00 00 00 00 58 C3 68 88 88 88 88 E9 3F E2 FF }
        $code_048_8 = { E8 00 00 00 00 58 C3 68 88 88 88 88 E9 AF E1 FF }
        $code_048_10 = { 44 00 89 3D 14 A4 44 00 66 8C 15 40 A4 44 00 66 }
        $code_064_1 = { FF C3 E8 00 00 00 00 58 C3 68 88 88 88 88 E9 82 }
        $code_064_3 = { FF C3 E8 00 00 00 00 58 C3 68 88 88 88 88 E9 F2 }
        $code_064_6 = { FF C3 E8 00 00 00 00 58 C3 68 88 88 88 88 E9 12 }
        $code_064_7 = { 8C 0D B4 CD 43 00 66 8C 1D 90 CD 43 00 66 8C 05 }
        $code_064_11 = { FF C3 E8 00 00 00 00 58 C3 68 88 88 88 88 E9 52 }
        $code_080_1 = { E2 FF FF C3 E8 00 00 00 00 58 C3 68 88 88 88 88 }
        $code_080_2 = { E1 FF FF C3 E8 00 00 00 00 58 C3 68 88 88 88 88 }
        $code_096_1 = { E9 85 E2 FF FF C3 E8 00 00 00 00 58 C3 68 88 88 }
        $code_096_2 = { 76 09 39 98 E8 00 40 00 0F 95 C3 89 5D E4 E8 89 }
        $code_096_8 = { A3 08 BF 40 00 89 0D 04 BF 40 00 89 15 00 BF 40 }
        $code_112_3 = { 88 88 E9 78 E2 FF FF C3 E8 00 00 00 00 58 C3 68 }
        $code_112_5 = { 88 88 E9 D8 E2 FF FF C3 E8 00 00 00 00 58 C3 68 }
        $code_112_6 = { 88 88 E9 48 E2 FF FF C3 E8 00 00 00 00 58 C3 68 }
        $code_112_12 = { 00 8B 45 04 A3 30 A4 44 00 8D 45 08 A3 3C A4 44 }
    condition:
        (General_WinPE_ValidPE and all of ($code_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_096_2 at (pe.entry_point + 96))
                or ($code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64) and $code_096_1 at (pe.entry_point + 96))
                or ($code_048_2 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80) and $code_112_3 at (pe.entry_point + 112))
                or ($code_048_5 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80) and $code_112_6 at (pe.entry_point + 112))
                or ($code_048_4 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80) and $code_112_5 at (pe.entry_point + 112))
                or ($ep_5 at (pe.entry_point + 0) and $code_032_3 at (pe.entry_point + 32) and $code_064_6 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_064_7 at (pe.entry_point + 64))
                or ($ep_6 at (pe.entry_point + 0) and $code_032_4 at (pe.entry_point + 32) and $code_064_3 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_7 at (pe.entry_point + 32) and $code_096_8 at (pe.entry_point + 96))
                or ($ep_9 at (pe.entry_point + 0) and $code_032_9 at (pe.entry_point + 32) and $code_064_11 at (pe.entry_point + 64))
                or ($ep_8 at (pe.entry_point + 0) and $code_048_8 at (pe.entry_point + 48) and $code_080_2 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_048_10 at (pe.entry_point + 48) and $code_112_12 at (pe.entry_point + 112))))
}

rule Virus_WinPE_Ramnit
{
    meta:
        description = "Stable Ramnit marker followed by its Srv.exe configuration value"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "family component; may match a dropper carrying the same payload"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $config = { 4B 79 55 66 66 54 68 4F 6B 59 77 52 52 74 67 50 50 00 53 72 76 2E 65 78 65 00 00 00 00 }
        $ep_1 = { 60 E8 00 00 00 00 5D 8B C5 81 ED 32 6F 01 20 2B }
        $ep_2 = { 60 E8 00 00 00 00 5D 8B C5 81 ED A8 A6 01 20 2B }
        $ep_3 = { 60 E8 00 00 00 00 5D 8B C5 81 ED CE B2 01 20 2B }
        $ep_4 = { 60 E8 00 00 00 00 5D 8B C5 81 ED 1E A5 01 20 2B }
        $code_032_2 = { B0 01 20 3C 01 0F 85 BC 01 00 00 83 BD 3B AF 01 }
        $code_032_3 = { BC 01 20 3C 01 0F 85 BC 01 00 00 83 BD 61 BB 01 }
        $code_032_4 = { AE 01 20 3C 01 0F 85 BC 01 00 00 83 BD B1 AD 01 }
        $code_064_1 = { 85 4C 72 01 20 2B 85 5C 72 01 20 8B 00 89 85 F2 }
        $code_064_2 = { AE 01 20 2B 85 3B AF 01 20 8B 00 89 85 78 AF 01 }
        $code_064_3 = { BA 01 20 2B 85 61 BB 01 20 8B 00 89 85 9E BB 01 }
        $code_064_4 = { AC 01 20 2B 85 B1 AD 01 20 8B 00 89 85 EE AD 01 }
    condition:
        (General_WinPE_ValidPE and $config)
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))
                or ($ep_4 at (pe.entry_point + 0) and $code_032_4 at (pe.entry_point + 32) and $code_064_4 at (pe.entry_point + 64))
                or ($ep_3 at (pe.entry_point + 0) and $code_032_3 at (pe.entry_point + 32) and $code_064_3 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_064_4 at (pe.entry_point + 64))
                or ($ep_2 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_2 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))))
}

rule Adware_MSIL_BrowseFox
{
    meta:
        description = "Static family string cluster for Adware_MSIL_BrowseFox"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "dynamic method does not support fault clause" ascii wide
        $family_2 = "c9885ab23d5026f036ba0580ac711ab7e`1" ascii wide
        $family_3 = "unexpected OperandType" ascii wide
        $family_4 = "_Encrypted$" ascii wide
        $family_5 = "c03d9098f2bdcf22c15f1d002de9d8402`1" ascii wide
        $family_6 = "c076561a2d817d4ec5a60a9bb67b60b3b`1" ascii wide
        $family_7 = "c0c9d08ace7dee3d63c60800fee80edb7`2" ascii wide
        $family_8 = "c11d5b5159e70aa7fab6a4a47dbbf06cc`3" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule Adware_MSIL_Linkury
{
    meta:
        description = "Static family string cluster for Adware_MSIL_Linkury"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = ", :UseChromeNewTab, :UseChromeDefaulSearch, :SearchProvidersPriorityListDS, :SearchProvidersPriorityListNT, :SearchProvi" ascii wide
        $family_2 = ":Enabled, :ChangeType, :ChangeRequestTimeDays, :SetHomepage, :SetDefaultSearchEngine, :SetBrowserSettingsSilently, :SetA" ascii wide
        $family_3 = ":LeftEdgeNormal, :LeftEdgeExpanded, :RightEdgeNormal, :RightEdgeExpanded, :LayoutElement, :Position, :Priority, :IsRemov" ascii wide
        $family_4 = ":Mode, :TopDomainsListSize, :DomainTimeDelta, :GlobalTimeDelta, :TopDomainsMaximum, :ViewsPerDay, :DbName, :SearchEngine" ascii wide
        $family_5 = "Chrome, :InstantSearchUrlChrome, :SearchUrlIE, :SearchUrlFF, :SearchNameChrome, :SearchNameIE, :SearchNameFF, :SearchDom" ascii wide
        $family_6 = "ddressBarSearch, :SetNewTab, :ReEnableExtension, :RefreshExtension, :ReInstallExtension, :InstallExtension, :Proprietary" ascii wide
        $family_7 = "dersPriorityListHP, :CheckChromeNewTabPorcessInterval, :ProtectorsDomainsWhiteList, :ProtectorsSearchUrlChrome, :Protect" ascii wide
        $family_8 = "ectionChannel, :PlayItIconPath, :SearchItIconPath, :FAQURL, :ShareItIconPath, :ServicesIconPath, :DisplaySimilarSites, :" ascii wide
        $family_9 = "ExtensionName, :PublisherGuid, :PublisherName, :AutoCompleteDescription, :FavIconUrl, :SearchUrl, :NonSearch, :SearchUrl" ascii wide
        $family_10 = "FF, :ProtectorsSearchDomain, :ProtectorsHomePageURLIE, :ProtectorsSearchUrlIE, :HostsFileMonitorLinkuryDomains, :BasicLi" ascii wide
        $family_11 = "global::Linkury.Personalization.Settings.PublisherSettingsManager.ContextMenuStripElementType" ascii wide
        $family_12 = "global::Linkury.Personalization.Settings.PublisherSettingsManager.LayoutElement" ascii wide
        $family_13 = "global::Linkury.Personalization.Settings.PublisherSettingsManager.ToolBarPanelEdgeStyle" ascii wide
        $family_14 = "HeaderLabel, :TrayWindowInfoLabel, :TrayWindowInfo2Label, :TrayWindowInfoNTLabel, :TrayWindowInfoDSLabel, :TakeDefaultSe" ascii wide
        $family_15 = "icsEndpoint, :EncryptURL, :MaxMindEndpoint, :BlackListServerFilePath, :BlackListLocalFilePath, :BlackListGetFileInterval" ascii wide
        $family_16 = "ierExePath, :DefaultMaxOrders, :DefaultInterval, :CheckingOffersIntervalInMinutes, :PrivateInvestigationEndpoint, :Short" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule Adware_WInPE_MyWebSearch
{
    meta:
        description = "Static family string cluster for Adware_WInPE_MyWebSearch"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "Mindspark Interactive Network1&0$" ascii wide
        $family_2 = "Mindspark Interactive Network0" ascii wide
        $family_3 = "Yonkers1&0$" ascii wide
        $family_4 = "http://eula.mindspark.com/ask/0" ascii wide
        $family_5 = "Mindspark Toolbar Platform for Internet Explorer" ascii wide
        $family_6 = "2009-2015 Mindspark Interactive Network, Inc." ascii wide
        $family_7 = "Mindspark Toolbar Platform" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule Adware_WinPE_Appster
{
    meta:
        description = "Static family string cluster for Adware_WinPE_Appster"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "Tyt-,TU(\\y&" ascii wide
        $family_2 = "@qwWoumMG(" ascii wide
        $family_3 = "q]sa\\BL!.Y" ascii wide
        $family_4 = "xAw0@KFU}t" ascii wide
        $family_5 = "!pX_C/oPh" ascii wide
        $family_6 = "8?ggs)yX'" ascii wide
        $family_7 = "ajCNg&R4U" ascii wide
        $family_8 = "h+W!AHZli" ascii wide
        $family_9 = "Ho1lOw.@9" ascii wide
        $family_10 = "JA+g&IGgj" ascii wide
        $family_11 = "Q{WoS%K@t" ascii wide
        $family_12 = "sq'4+bJz6" ascii wide
        $family_13 = "VlRfJ']Y[" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule Adware_WinPE_DownloadSponsor
{
    meta:
        description = "Static family string cluster for Adware_WinPE_DownloadSponsor"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "Accertarsi che il setup abbia i permessi per accedere ad internet" ascii wide
        $family_2 = "ber Start > Systemsteuerung > Programme (Start > Control Panel > Programs)" ascii wide
        $family_3 = "DownloadManager konnte nicht initialisiert werden. Beende das Setup." ascii wide
        $family_4 = "Klicken Sie auf weiter um [APP] auf ihrem Computer zu installieren." ascii wide
        $family_5 = "Klicken Sie auf Weiter, um [APP] auf Ihrem Computer zu installieren." ascii wide
        $family_6 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0; DSde) Gecko/20100101 Firefox/23.0" ascii wide
        $family_7 = "Per favore inserisci qui il tuo feedback e un commento sul perch" ascii wide
        $family_8 = "Please click the 'Next'-button in order to install [APP] on your PC." ascii wide
        $family_9 = "r allgemeine Windows-Steuerelemente und -Dialogfelder (Windows XP und h" ascii wide
        $family_10 = "Stellen Sie sicher dass das Setup auf das Internet zugreifen darf." ascii wide
        $family_11 = "Bitte geben Sie hier Ihr Feedback ein und teilen Sie uns mit," ascii wide
        $family_12 = "Sei sicuro di voler annullare l'installazione di [APPNAME]" ascii wide
        $family_13 = "You can uninstall it at Start > Control Panel > Programs)" ascii wide
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
}

rule Adware_WinPE_InstallMonstr
{
    meta:
        description = "High-confidence InstallMonstr entry-point code cluster"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
        refinement = "three correlated positional code features; generic SSL and MD5 library messages excluded"
    strings:
        $code_ep  = { 55 8B EC 83 C4 E4 53 56 57 33 C0 89 45 EC B8 38 }
        $code_096 = { 3C 09 61 00 FF 05 5C 09 61 00 83 3D 5C 09 61 00 }
        $code_208 = { FF E8 06 49 F6 FF 85 C0 74 48 B8 13 00 00 00 E8 }
    condition:
        General_WinPE_ValidPE and
        $code_ep at pe.entry_point and
        $code_096 at pe.entry_point + 96 and
        $code_208 at pe.entry_point + 208
}

rule Adware_WinPE_MailRu
{
    meta:
        description = "Static family string cluster for Adware_WinPE_MailRu"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "getTag() == JSON_ARRAY || getTag() == JSON_OBJECT" ascii wide
        $family_2 = "(uintptr_t)payload <= JSON_VALUE_PAYLOAD_MASK" ascii wide
        $family_3 = "getTag() == JSON_NUMBER" ascii wide
        $family_4 = "getTag() == JSON_STRING" ascii wide
        $family_5 = "Mail.Ru Launcher" ascii wide
        $family_6 = "--binded_data=\"" ascii wide
        $family_7 = "212=2B2P2T2b2f2" ascii wide
        $family_8 = "!isDouble()" ascii wide
        $family_9 = "LLC Mail.Ru0" ascii wide
        $family_10 = "LLC Mail.Ru1" ascii wide
        $family_11 = "D:\\Build\\desktop_apps\\launcher\\json/gason.h" ascii wide
        $family_12 = "D:\\Build\\desktop_apps\\_out\\launcher.pdb" ascii wide
        $family_13 = "\\lrunner.exe" ascii wide
        $family_14 = ".?AVHttpError@mailru@@" ascii wide
        $ep_1 = { E8 3C 72 00 00 E9 7F FE FF FF 55 8B EC 8B 45 08 }
        $code_016_1 = { 08 57 83 CF FF 85 F6 75 14 E8 AA 28 00 00 C7 00 }
        $code_032_2 = { 00 FF 30 E8 B9 00 00 00 8B C6 5E 5D C2 04 00 55 }
        $code_080_1 = { 85 C0 79 05 83 CF FF EB 13 83 7E 1C 00 74 0D FF }
        $code_080_2 = { 08 8B F1 83 66 04 00 C7 06 C0 DD 41 00 C6 46 08 }
        $code_128_1 = { 00 00 83 CF FF 89 7D E4 33 C0 8B 75 08 85 F6 0F }
    condition:
        ((General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80) and $code_128_1 at (pe.entry_point + 128))
                or ($ep_1 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_080_2 at (pe.entry_point + 80))))) and
        ($family_5 and $family_6)
}

rule Adware_WinPE_Syncopate
{
    meta:
        description = "Static family string cluster for Adware_WinPE_Syncopate"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "Global\\Thistle_{580D1956-62F4-40D8-B3A0-E2C1B7334726}" ascii wide
        $family_2 = "Select VideoProcessor from Win32_VideoController" ascii wide
        $family_3 = "Select PNPDeviceID from Win32_VideoController" ascii wide
        $family_4 = "Select EndingAddress from Win32_MemoryDevice" ascii wide
        $family_5 = "Select SerialNumber from win32_diskdrive" ascii wide
        $family_6 = "Select SoftwareElementID from Win32_BIOS" ascii wide
        $family_7 = "Select PNPDeviceID from win32_diskdrive" ascii wide
        $family_8 = "https://gnlogin.ru/?credentialkey=" ascii wide
        $family_9 = "Global Gamers Solutions Ltd. (c)" ascii wide
        $ep_1 = { E8 00 89 00 00 E9 89 FE FF FF CC CC CC CC CC 8B }
        $code_064_1 = { 04 72 31 F7 D9 83 E1 03 74 0C 2B D1 88 07 83 C7 }
    condition:
        ((General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("wininet.dll", "InternetOpenA") and pe.imports("wininet.dll", "InternetConnectA") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))) and
        ($family_1 and 3 of ($family_*))
}

rule Adware_WinPE_Trickler
{
    meta:
        description = "Static family string cluster for Adware_WinPE_Trickler"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "xddddph`XddddPH@8dddd0(" ascii wide
        $family_2 = "time error /LOSS" ascii wide
        $family_3 = "/to iniRaliz" ascii wide
        $family_4 = "erbose[pReq(" ascii wide
        $family_5 = "jwa \\QwTty+3" ascii wide
        $family_6 = ".2WH,jEUWT" ascii wide
        $family_7 = "n(,US_NDED" ascii wide
        $family_8 = "+Yr{PN-mo" ascii wide
        $family_9 = "-l?(lIVVP" ascii wide
        $family_10 = "/m,+e.asp" ascii wide
        $family_11 = "s/IMUDel2" ascii wide
        $family_12 = "tLVMW(M40" ascii wide
        $family_13 = "(PWShwg&" ascii wide
        $family_14 = "@VLvY+cY" ascii wide
        $code_064_1 = { 7C 43 43 00 C1 E1 08 03 CA 89 0D 78 43 43 00 C1 }
        $code_128_1 = { FC E8 18 3B 00 00 FF 15 38 62 42 00 A3 C0 5C 43 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_064_1 at (pe.entry_point + 64) and $code_128_1 at (pe.entry_point + 128))))
}

rule Adware_WinPE_Xetapp
{
    meta:
        description = "Static family string cluster for Adware_WinPE_Xetapp"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "+Kastelorizou, 6, 2nd floor, Flat/Office 2021" ascii wide
        $family_2 = "contact@xetapp.com0" ascii wide
        $family_3 = "Xetapp Limited0" ascii wide
        $family_4 = "Xetapp Limited1" ascii wide
        $family_5 = "EFWW3xW'7" ascii wide
        $family_6 = "aoO]]U-w" ascii wide
        $family_7 = "d2yboh?q" ascii wide
        $family_8 = "Ka4j]m_g" ascii wide
        $family_9 = "lXhXd(74" ascii wide
        $family_10 = "RTwe%3'U" ascii wide
        $family_11 = "Sf.uJ'P}" ascii wide
        $family_12 = "vlq?I$@J" ascii wide
        $ep_1 = { 55 89 E5 57 56 53 81 EC F8 02 00 00 68 01 80 00 }
        $code_032_1 = { F8 06 74 1E 83 EC 0C 6A 00 E8 BB 2D 00 00 83 C4 }
        $code_064_1 = { C4 0C BB BC B4 40 00 EB 16 83 EC 0C 53 E8 2C 2D }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule Backdoor_ASP_WebShell
{
    meta:
        description = "Static family string cluster for Backdoor_ASP_WebShell"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples containing ASP web-shell artifacts or payloads; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "JScript 0" ascii wide
        $family_2 = "AAAAXAAAAAAU!'AAnAAA?'AAnA6A;'AAnA" ascii wide
        $family_3 = "A!'AAnAAA?'AAnA6A;'AAnA" ascii wide
        $family_4 = "qAqAfA&ALAAAAAAAAAAA" ascii wide
        $family_5 = "A^'AAnAbAd'AAnA" ascii wide
        $family_6 = "AA6AA!%bA6AAA" ascii wide
        $family_7 = "6AAt%bAAAAA" ascii wide
        $family_8 = "A=SbAAAAA}" ascii wide
        $family_9 = "A9A!'AAnAAA?'AAnA6A;'AAnA" ascii wide
        $family_10 = "A;ALAHAVAxApA" ascii wide
        $family_11 = "AJA:AxA~AcAJA" ascii wide
        $family_12 = "LnAAAAAXAAAAAAU!'AAnAAA?'AAnA6A;'AAnA" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule Backdoor_MSIL_CobaltStrike
{
    meta:
        description = "Static family string cluster for Backdoor_MSIL_CobaltStrike"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "The hex string must have an even number of digits." ascii wide
        $family_2 = "$112e31fe-6f92-47db-9550-3bc153664d77" ascii wide
        $family_3 = "<InvokeUnmanagedFunction>b__6_0" ascii wide
    condition:
        General_WinPE_ValidPE and 2 of ($family_*)
}

rule Backdoor_MSIL_NetLoader
{
    meta:
        description = "Static family string cluster for Backdoor_MSIL_NetLoader"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "-ep bypass -command \"iex(get-content '" ascii wide
        $family_2 = "\\AppData\\Roaming\\solarmarker.dat" ascii wide
        $family_3 = "-ep bypass -command \"" ascii wide
        $family_4 = "JSON error!" ascii wide
    condition:
        General_WinPE_ValidPE and 2 of ($family_*)
}

rule Backdoor_MSIL_Remcos
{
    meta:
        description = "Static family string cluster for Backdoor_MSIL_Remcos"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "Enter a process name to open on the remote computer" ascii wide
        $family_2 = "Enter a url to open on the remote computer" ascii wide
        $family_3 = "<ServerSocket_onConnectionChanged>b__4_0" ascii wide
        $family_4 = "<ServerSocket_onConnectionChanged>b__5_0" ascii wide
        $family_5 = "<ServerSocket_onConnectionChanged>b__5_1" ascii wide
        $family_6 = "$2c60520e-e3cc-4b09-8d11-f25836f995fd" ascii wide
        $family_7 = "Remote_Administration_Tool.Properties" ascii wide
        $family_8 = "<ServerSocket_onDataReceived>b__4_0" ascii wide
        $family_9 = "Remote_Administration_Tool.Helpers" ascii wide
        $family_10 = "<ServerSocket_onDataReceived>b__0" ascii wide
        $family_11 = "<ServerSocket_onDataReceived>b__1" ascii wide
        $family_12 = "<ServerSocket_onListening>b__4_0" ascii wide
        $family_13 = "Remote_Administration_Tool.Forms" ascii wide
        $family_14 = "ServerSocket_onConnectionChanged" ascii wide
        $family_15 = "Start listening for connections" ascii wide
        $family_16 = "<ServerSocket_onListening>b__1" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule Backdoor_MSIL_SunBurst
{
    meta:
        description = "Static family string cluster for Backdoor_MSIL_SunBurst"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "(AlertDefID=@alertDefID{0} AND ActiveObject=@activeObject{0} AND ObjectType=@objectType{0})" ascii wide
        $family_2 = "(AlertID=@alertID{0} AND ObjectID=@objectID{0} AND ObjectType=@objectType{0})" ascii wide
        $family_3 = "({0}) AND (n.ObjectSubType IS NULL OR n.ObjectSubType <> 'Agent')" ascii wide
        $family_4 = ",[VolumeAllocationFailuresThisHour] = @VolumeAllocationFailuresThisHour" ascii wide
        $family_5 = ",[VolumeAllocationFailuresToday] = @VolumeAllocationFailuresToday" ascii wide
        $family_6 = ",WarningFormula,CriticalFormula,BaselineFrom,BaselineTo,BaselineApplied,BaselineApplyError" ascii wide
        $family_7 = ",WarningPolls,WarningPollsInterval,CriticalPolls,CriticalPollsInterval,WarningEnable" ascii wide
        $family_8 = "/Orion/Discovery/Results/ScheduledDiscoveryResults.aspx?Status={0}" ascii wide
        $family_9 = "@Old alerting will be removed. Use GetAlertList() method instead." ascii wide
        $family_10 = "Acknowledged, ActiveNetObject, NetObjectPrefix, SiteId, SiteName FROM" ascii wide
        $family_11 = "Acknowledged, ActiveNetObject, NetObjectPrefix, SiteId, SiteName FROM (" ascii wide
        $family_12 = "AlertActive.LastExecutedEscalationLevel, AlertActive.AcknowledgedDateTime, AlertActive.A" ascii wide
        $family_13 = "AND ActiveObject = @ActiveObject AND ObjectType LIKE @ObjectType" ascii wide
        $family_14 = "AND Events.EventTime >= @fromDate AND Events.EventTime <= @toDat" ascii wide
        $family_15 = "Basic pollers count = {0}, removed for NodeID = {1}, SubType = {2}" ascii wide
        $ep_1 = { FF 25 00 20 00 10 32 10 86 E8 5B DE 69 2C B2 3D }
        $code_064_1 = { 44 66 B1 41 0E C3 D7 8A 2C 29 8D FD 8A 4D 2C 25 }
        $implant_type = "OrionImprovementBusinessLayer" ascii fullword
        $implant_process = "GetProcessByDescription" ascii fullword
        $implant_customer = "GetOrionImprovementCustomerId" ascii fullword
        $implant_network = "GetNetworkAdapterConfiguration" ascii fullword
    condition:
        ((General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.data_directories[14].size > 0 and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))) and
        pe.data_directories[14].size > 0 and all of ($implant_*)
}

rule Backdoor_Win64_NukeSped
{
    meta:
        description = "NukeSped file-output and HTTP parsing marker cluster"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
        refinement = "requires both file-output anchors plus HTTP parser context"
    strings:
        $family_1 = "Can't create file %s, errno = %d" ascii wide
        $family_2 = "charset={[A-Za-z0-9\\-_]+}" ascii wide
        $family_3 = "Content-Length: {[0-9]+}" ascii wide
        $family_4 = "Set-Cookie:\\b*{.+?}\\n" ascii wide
        $family_5 = "%-20s   %10llu bytes" ascii wide
        $family_6 = "Location: {[0-9]+}" ascii wide
    condition:
        General_WinPE_ValidPE and
        $family_1 and $family_5 and 4 of ($family_*)
}

rule Backdoor_Win64_Winnti
{
    meta:
        description = "Static family string cluster for Backdoor_Win64_Winnti"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "\\Driver\\nsiproxy" ascii wide
        $family_2 = "C:\\Windows\\System32\\sysprep\\sysprep.exe" ascii wide
        $family_3 = "d$ LcL$(LcT$0H" ascii wide
        $family_4 = "C:\\Users\\test\\Error.txt" ascii wide
        $family_5 = "C:\\Users\\GX\\Error.log" ascii wide
        $family_6 = "\\drivers\\spliter.sys" ascii wide
        $family_7 = "\\Device\\PNTFILTER" ascii wide
        $family_8 = ".?AVCDrvCom@@" ascii wide
        $family_9 = "?RSDSu H" ascii wide
        $code_016_1 = { 8B F8 8B DA 48 8B F1 83 FA 01 75 05 E8 E7 1D 00 }
        $code_016_2 = { 8B F8 8B DA 48 8B F1 83 FA 01 75 05 E8 C3 1C 00 }
        $code_096_1 = { 00 8B DA 48 8B F9 48 89 01 E8 22 1E 00 00 F6 C3 }
        $code_224_1 = { 74 81 7D 00 63 73 6D E0 75 28 48 83 3D 36 80 00 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_224_1 at (pe.entry_point + 224))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_2 at (pe.entry_point + 16) and $code_096_1 at (pe.entry_point + 96))))
}

rule Backdoor_WinPE_Crysan
{
    meta:
        description = "Static family string cluster for Backdoor_WinPE_Crysan"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" ascii wide
        $family_2 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" ascii wide
        $family_3 = "Invalid message authentication code (MAC)." ascii wide
        $family_4 = "masterKey can not be null or empty." ascii wide
        $family_5 = "(ext8,ext16,ex32) type $c7,$c8,$c9" ascii wide
        $family_6 = "input can not be null." ascii wide
        $family_7 = "(never used) type $c1" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule Backdoor_WinPE_Dalatar
{
    meta:
        description = "Static family string cluster for Backdoor_WinPE_Dalatar"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "C:\\Users\\sryak\\Desktop\\iRaQ RAT\\Stub\\Client\\obj\\Debug\\Stub.pdb" ascii wide
        $family_2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Vitalwerks\\DUC" ascii wide
        $family_3 = "$5a542c1b-2d36-4c31-b039-26a88d3967da" ascii wide
        $family_4 = "HKEY_CURRENT_USER\\Software\\Paltalk\\" ascii wide
        $family_5 = "SELECT * FROM moz_disabledHosts;" ascii wide
        $family_6 = "\\Opera\\Opera\\profile\\wand.dat" ascii wide
        $family_7 = "\\FileZilla\\recentservers.xml" ascii wide
        $family_8 = "DynDNS\\Updater\\config.dyndns" ascii wide
        $family_9 = "SELECT * FROM moz_logins;" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule Backdoor_WinPE_Gamarue
{
    meta:
        description = "Static family string cluster for Backdoor_WinPE_Gamarue"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "E:\\Data\\My Projects\\Troy Source Code\\tcp1st\\rifle\\Release\\rifle.pdb" ascii wide
        $family_2 = "C:\\Program Files\\Common Files\\Update" ascii wide
        $family_3 = "Interval is set to %d min" ascii wide
        $family_4 = "C:\\ProgramData\\Update" ascii wide
        $family_5 = "MUTEX394039_4930023" ascii wide
        $family_6 = "\"C:\\Program Files\\Common Files\\Update\\wuauclt.exe\" /run" ascii wide
        $family_7 = "C:\\Program Files\\Common Files\\Update\\wuauclt.exe" ascii wide
        $family_8 = "\"C:\\ProgramData\\Update\\wuauclt.exe\" /run" ascii wide
        $family_9 = "C:\\ProgramData\\Update\\wuauclt.exe" ascii wide
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
}

rule Backdoor_WinPE_Havex
{
    meta:
        description = "Static family string cluster for Backdoor_WinPE_Havex"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "error, getting error text" ascii wide
        $family_2 = ".?AVHelp32Snapshot@_01@@" ascii wide
        $family_3 = ".?AVInetConnection@_01@@" ascii wide
        $family_4 = ".?AVLoggableThread@_02@@" ascii wide
        $family_5 = ".?AVRunnableThread@_01@@" ascii wide
        $family_6 = ".?AVPipeInterComm@_02@@" ascii wide
        $family_7 = ".?AVRemoteThread@_01@@" ascii wide
        $family_8 = ".?AVHttpRequest@_01@@" ascii wide
        $family_9 = ".?AVInetContext@_01@@" ascii wide
        $family_10 = ".?AVDllCommand@_02@@" ascii wide
        $family_11 = ".?AVInetHandle@_01@@" ascii wide
        $family_12 = ".?AVSafeHandle@_01@@" ascii wide
        $family_13 = ".?AVCsClient@_02@@" ascii wide
        $family_14 = ".?AVProcess@_01@@" ascii wide
        $ep_1 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 7A 85 00 00 }
        $ep_2 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 42 85 00 00 }
        $ep_3 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 8A 85 00 00 }
        $ep_4 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 36 7C 00 00 }
        $code_064_1 = { 04 E8 56 87 00 00 59 83 65 FC 00 56 E8 7E 87 00 }
        $code_064_3 = { E8 C9 34 00 00 83 C4 0C E9 AA 33 00 00 6A 0C 68 }
        $code_064_5 = { 04 E8 66 87 00 00 59 83 65 FC 00 56 E8 8E 87 00 }
        $code_112_2 = { E4 00 75 37 FF 75 08 EB 0A 6A 04 E8 0A 86 00 00 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_2 at (pe.entry_point + 0) and $code_112_2 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_4 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_3 at (pe.entry_point + 0) and $code_064_5 at (pe.entry_point + 64))))
}

rule Backdoor_WinPE_IRCBot
{
    meta:
        description = "Static family string cluster for Backdoor_WinPE_IRCBot"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\" ascii wide
        $family_2 = "\\WINNT\\Profiles\\All Users\\Start Menu\\Programs\\Startup\\" ascii wide
        $family_3 = "\\WINDOWS\\Start Menu\\Programs\\Startup\\" ascii wide
        $family_4 = ":Added Random Garbage To (" ascii wide
        $family_5 = "(netbios_accessdenied:" ascii wide
        $family_6 = "(netbios_logonfailure:" ascii wide
        $family_7 = "(netbios_invalidpass:" ascii wide
        $family_8 = "(scan_infectedfiles:" ascii wide
        $family_9 = "(scan_infecteddirs:" ascii wide
        $family_10 = "(netbios_infected:" ascii wide
        $family_11 = "(mydoom_infected:" ascii wide
        $family_12 = "QUIT :Updating..." ascii wide
        $family_13 = "(netbios_failed:" ascii wide
        $family_14 = "BattleField 1942" ascii wide
        $family_15 = "(mydoom_failed:" ascii wide
        $family_16 = "(netbios_tries:" ascii wide
        $code_064_1 = { 40 00 33 D2 89 10 A1 70 B1 40 00 33 D2 89 10 A1 }
        $code_128_1 = { 00 33 D2 89 10 E8 76 CF FF FF B8 88 D1 40 00 BA }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_064_1 at (pe.entry_point + 64) and $code_128_1 at (pe.entry_point + 128))))
}

rule Backdoor_WinPE_LolBot
{
    meta:
        description = "Static family string cluster for Backdoor_WinPE_LolBot"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "oePari.recFtutMSrtiipSnsaldzLereiati.eeecllYt.rlPeinvsrnhoCtdryeiSrSaPrdstisedonu.As..cTohmooAtCc.warsrSc.SAaElaelfp" ascii wide
        $family_2 = "JUthnaac,uvdSdSapee" ascii wide
        $family_3 = "\\VirtualDevice.vxd" ascii wide
        $family_4 = "849557;=@<A==?CEHDIEEGKMPLQMMOSUXTYUUW[]`\\a]]_cehdieegkm7c;i7>i9?kCq?FqAGsKyGNyIO{S" ascii wide
        $family_5 = "b72e56767?:m=>?>?GBuEFGFGOJ}MNONOWR" ascii wide
        $family_6 = "jjoq5568==j7==>@EEr?EEFHMMzGMMNPUU" ascii wide
        $family_7 = "fef9ec7;;gkAmk?CCosIusGKKw{Q}{OSS" ascii wide
        $family_8 = "_a11d5e9i799l=mAq?AAtEuIyGII|M}Q" ascii wide
        $family_9 = "efgf9d67h::?Al>?pBBGItFGxJJOQ|NO" ascii wide
        $family_10 = "f98:48?8nA@B<@G@vIHJDHOH~QPRLPWP" ascii wide
        $family_11 = "nhqc83:6g=jk@;B>oErsHCJFwMz{PKRN" ascii wide
        $family_12 = "_ab1:d:h?lj9BlBpGtrAJtJxO|zIR|R" ascii wide
        $family_13 = "beb5;87i6=j=C@?q>ErEKHGyFMzMSPO" ascii wide
        $family_14 = "1b7e7:k79j?m?Bs?ArGuGJ{GIzO}OR" ascii wide
        $family_15 = "915<f:h?A9=DnBpGIAELvJxOQIMT~R" ascii wide
        $family_16 = "om173eg9hi9?;moApqAGCuwIxyIOK}" ascii wide
        $ep_1 = { 55 89 E5 6A FF 68 40 65 40 00 68 48 45 40 00 64 }
        $code_032_1 = { 53 56 57 89 65 E8 68 00 00 00 02 E8 40 0B 00 00 }
        $code_064_1 = { 01 E8 4A 01 00 00 59 C7 45 FC 00 00 00 00 E8 CD }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule Backdoor_WinPE_Outbreak
{
    meta:
        description = "Static family string cluster for Backdoor_WinPE_Outbreak"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = ":0:5:@:E:P:U:`:e:p:x:}:" ascii wide
        $family_2 = ":-:=:P:Z:^:d:h:m:t:z:" ascii wide
        $family_3 = "4#4/4:4E4O4Z4d4o4y4" ascii wide
        $family_4 = "595H5X5d5h5p5t5x5|5" ascii wide
        $family_5 = "575C5J5U5_5i5t5~5" ascii wide
        $family_6 = "7!848G8]8b8m8r8w8" ascii wide
        $family_7 = "?%???E?K?P?f?n?x?" ascii wide
        $family_8 = "TStringList,G@" ascii wide
        $family_9 = ">B?R?]?c?k?p?" ascii wide
        $family_10 = "TStrings$F@" ascii wide
        $family_11 = "EliRT 1.01" ascii wide
        $code_016_1 = { 53 B8 98 33 14 13 E8 85 ED FF FF 33 C0 55 68 23 }
        $code_080_1 = { C6 00 02 BA 01 00 00 00 B8 A8 56 15 13 E8 CA E4 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "WriteProcessMemory") and pe.imports("kernel32.dll", "CreateRemoteThread") and $code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80))))
}

rule Backdoor_WinPE_Quasar
{
    meta:
        description = "Static family string cluster for Backdoor_WinPE_Quasar"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "ClientIdentificationResult" ascii wide
        $family_2 = "ReportProgressEventHandler" ascii wide
        $family_3 = "GetKeyloggerLogsDirectory" ascii wide
        $family_4 = "MessageProcessorBase`1" ascii wide
        $family_5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0" ascii wide
        $family_6 = "Successfully displayed MessageBox" ascii wide
        $family_7 = "Getting Autostart Items failed:" ascii wide
        $family_8 = "Removing Autostart Item failed:" ascii wide
        $family_9 = ">> Session unexpectedly closed" ascii wide
        $family_10 = "Adding Autostart Item failed:" ascii wide
        $family_11 = "<ContainsModifierKeys>b__0_0" ascii wide
        $family_12 = "Uninstalling... good bye :-(" ascii wide
        $family_13 = "<DisableScreensaver>b__22_0" ascii wide
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*)) and
        (pe.data_directories[14].size > 0 and $family_1 and $family_3 and 1 of ($family_7, $family_8, $family_10))
}

rule Backdoor_WinPE_Revcode
{
    meta:
        description = "Static family string cluster for Backdoor_WinPE_Revcode"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "http:/are/m4" ascii wide
        $family_2 = "Nnnnnb2,lld" ascii wide
        $family_3 = "nnnnb2,ll@" ascii wide
        $family_4 = "6$6,646<6D6L6T6\\6d6l6t6\\7`7d7h7p7t7x7|7" ascii wide
        $ep_1 = { 55 8B EC 83 C4 F0 B8 98 45 45 00 E8 FC 14 FB FF }
        $code_192_1 = { 78 22 40 00 F8 25 40 00 00 CB CC C8 C9 D7 CF C8 }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_192_1 at (pe.entry_point + 192))))
}

rule Backdoor_WinPE_Rizees
{
    meta:
        description = "Static family string cluster for Backdoor_WinPE_Rizees"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "\"C:\\Program Files\\WPS Office\\11.1.0.10148\\office6\\wp" ascii wide
        $family_2 = "https://gitee.com/lenovo/mycode/raw/trojan/main.cpp" ascii wide
        $family_3 = "s.exe\" \"D:\\MyPrivateFiles\\private.doc\"" ascii wide
        $family_4 = "CreateThread failed! Error code: %d" ascii wide
        $family_5 = "Not running in a virtual machine" ascii wide
        $family_6 = "hz.exe a -tzip photo.zip d:\\jpg" ascii wide
        $family_7 = "Running in a virtual machine" ascii wide
        $family_8 = "No debugger detected" ascii wide
        $family_9 = "\\winnet.exe" ascii wide
        $family_10 = "IIS Angent" ascii wide
        $family_11 = "1%1/161>1E1K1R1X1b1j1v1" ascii wide
        $ep_1 = { E8 BF 03 00 00 E9 7A FE FF FF E9 C8 0A 00 00 55 }
        $ep_2 = { E8 BF 03 00 00 E9 7A FE FF FF E9 CE 0A 00 00 55 }
        $code_144_1 = { C0 04 50 E8 03 0A 00 00 59 59 8B C6 5E 5D C2 04 }
        $code_144_2 = { C0 04 50 E8 09 0A 00 00 59 59 8B C6 5E 5D C2 04 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_144_1 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_144_2 at (pe.entry_point + 144))))
}

rule Backdoor_WinPE_Winnit
{
    meta:
        description = "Static family string cluster for Backdoor_WinPE_Winnit"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "XX241B94-028A-441D-B9EB-B9AD3FDF2DBB" ascii wide
        $family_2 = "HookAPIs ...PID %d" ascii wide
        $family_3 = ".?AVCsLock@@" ascii wide
        $family_4 = "\\pciexij.dll" ascii wide
        $family_5 = "XX241B94-028A-441D-B9EB-B9AD3FDF0308" ascii wide
        $family_6 = "LOGENTRY_THREADCACHE_MALLOC" ascii wide
        $family_7 = "LOGENTRY_THREADCACHE_CLEAN" ascii wide
        $family_8 = "LOGENTRY_THREADCACHE_FREE" ascii wide
        $family_9 = "A at L %d" ascii wide
        $family_10 = "H:\\Double\\Door_wh\\ShutDownEvent\\Release\\ShutDownEvent.pdb" ascii wide
        $family_11 = "H:\\Double\\Door_wh\\AppInit\\Release\\AppInit.pdb" ascii wide
        $family_12 = "7,7074787<7D7H7P7T7X7\\7t7x7|7" ascii wide
        $family_13 = "8 8(8,80848L8P8T8X8\\8d8h8|9" ascii wide
        $family_14 = "9!9&91979;9A9Q9W9[9a9h9l9q9" ascii wide
        $family_15 = "7%7-797F7?8E8P8]8c8k8p8}8" ascii wide
        $code_016_1 = { FF 85 C0 74 5B 83 3D B8 C0 05 10 00 75 52 8B 44 }
        $code_080_1 = { 00 83 C4 0C 85 C0 74 18 8B 15 74 BF 05 10 8B 0D }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80))))
}

rule Backdoor_WinPE_XWorm
{
    meta:
        description = "Static family string cluster for Backdoor_WinPE_XWorm"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "$3fe8fa79-5dce-4503-ab23-464ea24babff" ascii wide
        $family_2 = "\\diagnosH" ascii wide
        $family_3 = "nostics\\H" ascii wide
        $family_4 = "8g2KbNcr2ZFrFZBWZ9C7dw==" ascii wide
        $family_5 = "aN9cu9ILSKnk11H1+PqZDw==" ascii wide
        $family_6 = "zbUo+zL7eHA+vmtqoro1Sg==" ascii wide
        $family_7 = "\\diagnosI" ascii wide
        $family_8 = "1XKaDo3xActIcb0HEgcMrw==" ascii wide
        $family_9 = "r5yszwhAfqBrEU3y55gzwg==" ascii wide
        $family_10 = "UF4eltTYyn7yuN24dZYpqQ==" ascii wide
        $ep_1 = { 48 83 EC 28 E8 0F 00 00 00 48 83 C4 28 E9 7A FE }
        $code_064_1 = { 48 8D 4D 10 FF 15 22 80 03 00 48 8B 45 10 48 89 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Backdoor_WinPE_Xtrat
{
    meta:
        description = "Static family string cluster for Backdoor_WinPE_Xtrat"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "WVXEGHF@A" ascii wide
        $family_2 = "jiejwogfdjieovevodnvfnievn" ascii wide
        $family_3 = "frgjbfdkbnfsdjbvofsjfrfre" ascii wide
        $family_4 = "SOFTWARE\\XtremeRAT" ascii wide
        $family_5 = "UnitInjectProcess" ascii wide
        $family_6 = "%DEFAULTBROWSER%" ascii wide
        $family_7 = "[Previous Track]" ascii wide
        $family_8 = "UnitInjectServer" ascii wide
        $family_9 = "UnitCryptString" ascii wide
        $family_10 = "XtremeKeylogger" ascii wide
        $family_11 = "[Context Menu]" ascii wide
        $family_12 = "[Play / Pause]" ascii wide
        $family_13 = "[Print Screen]" ascii wide
        $family_14 = "[Arrow Right]" ascii wide
        $family_15 = "[Mode Change]" ascii wide
        $family_16 = "[Volume Down]" ascii wide
        $ep_1 = { 55 8B EC B9 BC 02 00 00 6A 00 6A 00 49 75 F9 53 }
        $code_064_1 = { 01 68 07 80 00 00 E8 E1 7D FF FF 8D 55 EC B8 01 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Exploit_CVE_2021_41379
{
    meta:
        description = "Static family string cluster for Exploit_CVE_2021_41379"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples containing exploit-related artifacts; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "public CVE label; malware-family attribution not applicable"
    strings:
        $code_016_1 = { FF FF CC CC 48 83 61 10 00 48 8D 05 54 16 00 00 }
        $code_080_1 = { 07 00 00 CC E9 63 08 00 00 CC CC CC 48 83 EC 28 }
        $code_128_1 = { 48 0F B1 0D 14 47 00 00 75 EE 32 C0 48 83 C4 28 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80) and $code_128_1 at (pe.entry_point + 128))))
}

rule HackTool_MSIL_PoshC2
{
    meta:
        description = "Static family string cluster for HackTool_MSIL_PoshC2"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "...................@..........................Tyscf" ascii wide
        $family_2 = "[+] Running background task" ascii wide
        $family_3 = "!d-3dion@LD!-d" ascii wide
        $family_4 = "SessionID={0}" ascii wide
        $family_5 = "URLS10484390243(.*)34209348401SLRU" ascii wide
        $family_6 = "RANDOMURI19901(.*)10991IRUMODNAR" ascii wide
        $family_7 = "NEWKEY8839394(.*)4939388YEKWEN" ascii wide
        $family_8 = "run-exe Core.Program Core {0}" ascii wide
        $family_9 = "IMGS19459394(.*)49395491SGMI" ascii wide
        $family_10 = "KILLDATE1665(.*)5661ETADLLIK" ascii wide
        $family_11 = "<ImplantCore>c__AnonStorey1" ascii wide
        $family_12 = "JITTER2025(.*)5202RETTIJ" ascii wide
        $family_13 = "SLEEP98001(.*)10089PEELS" ascii wide
        $family_14 = "Beacon set" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule HackTool_WinPE_CABED
{
    meta:
        description = "Static family string cluster for HackTool_WinPE_CABED"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "LockResource or SizeofResource failed." ascii wide
        $family_2 = "CreateNamedPipeW failed. Error:" ascii wide
        $family_3 = "__DLL_PIPE_COMPLETION_SIGNAL__" ascii wide
        $family_4 = "Architecture match: Injector=" ascii wide
        $family_5 = "PeekNamedPipe failed. Error:" ascii wide
        $family_6 = "FindResource failed. Error:" ascii wide
        $family_7 = "LoadResource failed. Error:" ascii wide
        $family_8 = "Named pipe server created:" ascii wide
        $family_9 = "Terminating browser PID=" ascii wide
        $family_10 = "terminated by injector." ascii wide
        $family_11 = "Sent message to pipe:" ascii wide
        $family_12 = "Found and sorted" ascii wide
        $family_13 = "Zw* functions." ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule HackTool_WinPE_Mimikatz
{
    meta:
        description = "Static family string cluster for HackTool_WinPE_Mimikatz"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "Compatibility prefered key:" ascii wide
        $family_2 = "Current prefered key:" ascii wide
        $family_3 = "* MasterKey :" ascii wide
        $family_4 = "<no size, buffer is incorrect>" ascii wide
        $family_5 = "* Unknown key (seen as %08x)" ascii wide
        $family_6 = "Logon Server      : %wZ" ascii wide
        $family_7 = "Domain: %wZ (%wZ" ascii wide
        $family_8 = "PIN code : %wZ" ascii wide
        $family_9 = "%s krbtgt:" ascii wide
        $family_10 = "unkData2 :" ascii wide
        $family_11 = "(&(|(objectClass=user)(objectClass=computer))(sAMAccountName=%s$))" ascii wide
        $family_12 = "** Session key is NULL! It means allowtgtsessionkey is not set to 1 **" ascii wide
        $family_13 = "> blocks[0] indicates PWD, blocks[7] will be the password (0x%08x)" ascii wide
        $family_14 = "[experimental] patch Terminal Server service to allow multiples users" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule HackTool_WinPE_PrintSpoofer
{
    meta:
        description = "Static family string cluster for HackTool_WinPE_PrintSpoofer"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "CreateProcessWithTokenW() failed. Error: %d" ascii wide
        $family_2 = "12345678-1234-ABCD-EF00-0123456789AB" ascii wide
        $family_3 = "DuplicateTokenEx() failed. Error: %d" ascii wide
        $family_4 = "[!] CreateProcessWithTokenW() isn't compatible with option -i" ascii wide
        $family_5 = "CreateEnvironmentBlock() failed. Error: %d" ascii wide
        $family_6 = "CreateProcessAsUser() failed. Error: %d" ascii wide
        $family_7 = "ImpersonateNamedPipeClient(). Error: %d" ascii wide
        $family_8 = "SetTokenInformation() failed. Error: %d" ascii wide
        $family_9 = "GetSystemDirectory() failed. Error: %d" ascii wide
        $family_10 = "OpenThreadToken(). Error: %d" ascii wide
        $family_11 = "\\\\.\\pipe\\%ws\\pipe\\spoolss" ascii wide
        $family_12 = "\\\\%ws/pipe/%ws" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule HackTool_WinPE_Vbinder
{
    meta:
        description = "Static family string cluster for HackTool_WinPE_Vbinder"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "C:\\Users\\DarkCoderSc\\Desktop\\Celesty Binder\\Stub\\STATIC\\Stub.pdb" ascii wide
        $family_2 = "2!3'3,3;3B3H3N3c3h3p3u3|3x4" ascii wide
        $family_3 = "1%1*1/15191?1D1J1O1^1t1z1" ascii wide
        $family_4 = "4D4J4Y4=5C5U5l6q6{6" ascii wide
        $family_5 = "1$2C2U2^2e2m2t2" ascii wide
        $family_6 = "4D5X5`5h5p5t5x5" ascii wide
        $family_7 = "%STARTUPDIR%" ascii wide
        $family_8 = "%PROGFILES%" ascii wide
        $family_9 = "%DEFDRIVE%" ascii wide
        $family_10 = "%LAPPDATA%" ascii wide
        $ep_1 = { E8 26 1F 00 00 E9 89 FE FF FF 8B FF 55 8B EC 83 }
        $code_064_1 = { 45 F4 50 FF 75 F0 FF 75 E4 FF 75 E0 FF 15 58 90 }
    condition:
        (General_WinPE_AnySizePE and 3 of ($family_*))
        or (General_WinPE_AnySizePE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Ransom_WinPE_Akira
{
    meta:
        description = "Static family string cluster for Ransom_WinPE_Akira"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "asio::random_access_handle error:" ascii wide
        $family_2 = "write_encrypt_info error:" ascii wide
        $family_3 = "async_all_write failed:" ascii wide
        $family_4 = "--encryption_percent" ascii wide
        $family_5 = "Error message file :" ascii wide
        $family_6 = "Error shared file :" ascii wide
        $family_7 = "--encryption_path" ascii wide
    condition:
        ((General_WinPE_ValidPE and 3 of ($family_*))) and
        ($family_2 and 1 of ($family_4, $family_7))
}

rule Ransom_WinPE_Fakeup
{
    meta:
        description = "Static family string cluster for Ransom_WinPE_Fakeup"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = ":: Create profile directory (same as WhatsAppPlugin Launch function)" ascii wide
        $family_2 = "[-] Edge output folder does not exist (checked both Edge and edge)" ascii wide
        $family_3 = "[-] Edge output folder does not exist - DLL did not create files" ascii wide
        $family_4 = "[-] Edge output folder exists but is empty - DLL may not have completed" ascii wide
        $family_5 = "Delete all the files here, then copy the stolen files to this folder" ascii wide
        $family_6 = "ion=-10000,-10000 --window-size=1,1 --disable-features=RendererCodeIntegrity about:blank" ascii wide
        $family_7 = "mkdir \"%DEF%\\IndexedDB\\https_web.whatsapp.com_0.indexeddb.leveldb\" 2>nul" ascii wide
        $family_8 = "open this file path on your computer <%appdata%\\Telegram Desktop\\tdata>." ascii wide
        $family_9 = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" ascii wide
        $family_10 = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0001" ascii wide
        $family_11 = "2. Go to: %localappdata%\\EpicGamesLauncher\\Saved\\Config\\Windows" ascii wide
        $family_12 = ":: Find available sessions (Browser sessions first, then Store)" ascii wide
        $family_13 = "echo     Make sure session folders exist with IndexedDB data." ascii wide
        $family_14 = "if exist \"%WA_PKG%\\LocalState\\EBWebView\\Default\\IndexedDB\" (" ascii wide
        $family_15 = ") else if exist \"%WA_PKG%\\LocalState\\EBWebView\\IndexedDB\" (" ascii wide
        $family_16 = ":: Also check Store sessions (can be restored via browser)" ascii wide
        $ep_1 = { 48 83 EC 28 48 8B 05 45 6F 02 00 C7 00 01 00 00 }
        $code_128_1 = { 41 56 41 55 41 54 57 56 53 48 81 EC 68 02 00 00 }
        $code_144_1 = { 31 D2 48 89 CB B9 02 00 00 00 FF 15 A8 A7 02 00 }
        $code_208_1 = { 48 8D 7C 24 4C 0F 1F 00 48 89 DA 48 89 F9 FF 15 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_144_1 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_128_1 at (pe.entry_point + 128) and $code_208_1 at (pe.entry_point + 208))))
}

rule Ransom_WinPE_GandCrab
{
    meta:
        description = "Static family string cluster for Ransom_WinPE_GandCrab"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "/c timeout -c 5 & del \"%s\" /f /q" ascii wide
        $family_2 = "agntsvc.exeisqlplussvc.exe" ascii wide
        $family_3 = "NortonAntiBot.exe" ascii wide
        $family_4 = "ransom_id=" ascii wide
        $family_5 = "{USERID}" ascii wide
        $ep_1 = { 55 8B EC 83 EC 0C C7 45 F4 01 00 00 00 8B 45 0C }
        $code_048_1 = { 6A 40 8B F1 33 FF 68 00 30 00 00 50 57 89 7E 08 }
        $code_080_1 = { 55 8B EC 83 EC 5C 56 6A 44 8D 45 A8 0F 57 C0 6A }
        $code_112_1 = { 8B D1 56 83 7A 08 00 74 19 8B 72 04 8B 4D 08 03 }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_080_1 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_048_1 at (pe.entry_point + 48) and $code_112_1 at (pe.entry_point + 112))))
}

rule Ransom_WinPE_Trigona
{
    meta:
        description = "Static family string cluster for Ransom_WinPE_Trigona"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "PSafeCallExption]" ascii wide
        $family_2 = "k has occ0d." ascii wide
        $family_3 = "?[SUPPORT]/" ascii wide
        $family_4 = "LibModuP%/T" ascii wide
        $family_5 = "Tw$gitYe6C)" ascii wide
        $family_6 = "&op_Equity" ascii wide
        $family_7 = "/open_kecf" ascii wide
        $family_8 = "Cn2ncoZ@Ku" ascii wide
        $family_9 = "Syk8ZEA!CJ" ascii wide
        $family_10 = "bXW[vnero" ascii wide
        $family_11 = "An unEE]" ascii wide
        $ep_1 = { 60 BE 00 E0 43 00 8D BE 00 30 FC FF C7 87 0C FC }
        $code_240_1 = { 04 77 F1 01 CF E9 2C FF FF FF 5E 89 F7 B9 A0 19 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_240_1 at (pe.entry_point + 240))))
}

rule Rootkit_WinPE_Hooks
{
    meta:
        description = "Static family string cluster for Rootkit_WinPE_Hooks"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = ".\\i386\\RESSDT.sys" ascii wide
        $family_2 = "y\\Registry\\Machine\\SOFTWARE" ascii wide
        $family_3 = "SSDT Stack" ascii wide
        $ep_1 = { 55 8B EC 51 51 57 68 D2 04 01 00 E8 7C 00 00 00 }
        $code_032_1 = { C7 42 70 80 05 01 00 C7 42 34 7C 05 01 00 90 8D }
        $code_064_1 = { 90 90 8D 45 F8 50 E8 C3 FD FF FF 33 C0 5F C9 C2 }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule Rootkit_WinPE_NetFilter
{
    meta:
        description = "Static family string cluster for Rootkit_WinPE_NetFilter"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = "!D$X!D$PH!D$HH!E" ascii wide
        $family_2 = "p]Juutmmu_euualoUIirmqolt'Umwu`n`uT@ngnbe|jngs" ascii wide
        $family_3 = "URbaapu{y[Ki`i`nbZ[LG]WFTM_L`cui{lg}\\T" ascii wide
        $family_4 = "p]Juutmmu_euualoUIirmqolt'Umwu`n`u" ascii wide
        $family_5 = "LnfddfMlgfeqBt}oWtg{xOefr}qdz" ascii wide
        $family_6 = "@nsczmd} Tc|whggt" ascii wide
        $family_7 = "Difmdjtnif9!jlhum" ascii wide
        $family_8 = "UDbpa`dUnbrnjm}eu" ascii wide
        $family_9 = "URbaapu{y[S{fsU" ascii wide
        $family_10 = "HusiKlooi`SZO" ascii wide
        $family_11 = "U?8Zffuoikrmq" ascii wide
        $code_016_1 = { E8 4B 4E 01 00 48 8B D3 48 8B CF 48 8B 5C 24 30 }
        $code_048_1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 05 27 A6 00 }
        $code_096_1 = { 48 85 C0 74 18 4C 8B 05 EC 36 01 00 48 8D 0D 5D }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_016_1 at (pe.entry_point + 16) and $code_048_1 at (pe.entry_point + 48) and $code_096_1 at (pe.entry_point + 96))))
}

rule TrojanDownloader_AutoIT_NetLoader
{
    meta:
        description = "Static family string cluster for TrojanDownloader_AutoIT_NetLoader"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples containing AutoIt-related artifacts or payloads; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "(Xjvsupport@ahit" ascii wide
        $family_2 = "O_START_OPT)IMI" ascii wide
        $family_3 = "vovuttNNNn?srqq" ascii wide
        $family_4 = "m?llkrrr;jojih" ascii wide
        $family_5 = "`tyRof$&lo( s" ascii wide
        $family_6 = "Uhpt4s.V;(/A." ascii wide
        $family_7 = "} quantifiKzo" ascii wide
        $family_8 = "/fngPi1L0cP" ascii wide
        $family_9 = "10&sinh?os" ascii wide
        $family_10 = "c\\&pcalstd" ascii wide
        $family_11 = "n0,uu'bPjt" ascii wide
        $ep_1 = { 60 BE 00 C0 48 00 8D BE 00 50 F7 FF 57 EB 0B 90 }
        $code_224_1 = { 04 77 F1 01 CF E9 2C FF FF FF 5E 89 F7 B9 EF 3E }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_224_1 at (pe.entry_point + 224))))
}

rule TrojanDownloader_HTML_Agent
{
    meta:
        description = "Static family string cluster for TrojanDownloader_HTML_Agent"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples containing HTML artifacts or payloads; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
        confidence = "high"
    strings:
        $family_1 = "2Auto Posto Silvestre Comercio de Combustiveis LTDA1;09" ascii wide
        $family_2 = "2Auto Posto Silvestre Comercio de Combustiveis LTDA0" ascii wide
        $family_3 = "contato@gocorrespondente.com0" ascii wide
    condition:
        General_WinPE_ValidPE and 2 of ($family_*)
}

rule TrojanDownloader_MSIL_Cust
{
    meta:
        description = "Static family string cluster for TrojanDownloader_MSIL_Cust"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
        confidence = "high"
    strings:
        $family_1 = "EAMY_WINEHOUSEntAMY_WINEHOUSEryAMY_WINEHOUSEPoAMY_WINEHOUSEinAMY_WINEHOUSEt" ascii wide
        $family_2 = "AMY_WINEHOUSEaAMY_WINEHOUSEmAMY_WINEHOUSEsAMY_WINEHOUSEi.dll" ascii wide
        $family_3 = "AsAMY_WINEHOUSEseAMY_WINEHOUSEmbAMY_WINEHOUSElAMY_WINEHOUSEy" ascii wide
        $family_4 = "AMY_WINEHOUSEGeAMY_WINEHOUSEtTAMY_WINEHOUSEypAMY_WINEHOUSEe" ascii wide
        $family_5 = "AMY_WINEHOUSEInAMY_WINEHOUSEvoAMY_WINEHOUSEkAMY_WINEHOUSEe" ascii wide
        $family_6 = "AMY_WINEHOUSELAMY_WINEHOUSEoaAMY_WINEHOUSEd" ascii wide
        $family_7 = "<GetTextBetweenDelimiters>b__1_0" ascii wide
        $family_8 = "C:\\Users\\85858558559--\\FaceRecognitionService-master-master\\obj\\Debug\\FaceRecogService.pdb" ascii wide
        $family_9 = "C:\\ImageProcessing\\Images\\Destination\\" ascii wide
        $family_10 = "$f8750c8c-5b89-44bd-90e4-c3ebc3b153a1" ascii wide
        $family_11 = "Rpi_ImageRecognitionService@gmail.com" ascii wide
        $family_12 = "C:\\ImageProcessing\\Images\\Detected\\" ascii wide
        $family_13 = "FaceRecogService aaa aaa aaa aaa" ascii wide
        $family_14 = "http://138.91.36.91:8000/Service" ascii wide
        $family_15 = "Mail with Image as attachment" ascii wide
        $family_16 = "FaceRecogService aa aaa aaa" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule TrojanDownloader_Win64_Maloader
{
    meta:
        description = "Static family string cluster for TrojanDownloader_Win64_Maloader"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = "xeon1488ss@gmail.com0" ascii wide
        $family_2 = "xeon1488ss@gmail.com" ascii wide
        $family_3 = "Windows Optimizer" ascii wide
        $family_4 = "Danya Pidor1#0!" ascii wide
        $ep_1 = { 48 83 EC 28 48 8B 05 D5 53 00 00 C7 00 01 00 00 }
        $code_112_1 = { 55 53 48 83 EC 38 48 8D 6C 24 30 48 8D 0D 9E 4B }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_112_1 at (pe.entry_point + 112))))
}

rule TrojanDownloader_WinPE_Garveep
{
    meta:
        description = "Static family string cluster for TrojanDownloader_WinPE_Garveep"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "GTE CyberTrust Global Root0" ascii wide
        $family_2 = "%PROGRAMFILES%\\Virusbuster\\Internet Security Suite\\op_mon.exe" ascii wide
        $family_3 = "ssasv\\eje" ascii wide
        $ep_1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 E3 2D 00 00 }
        $code_016_2 = { F6 75 09 83 3D 4C 84 04 10 00 EB 26 83 FE 01 74 }
        $code_080_1 = { D9 A6 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 }
        $code_128_1 = { 74 11 A1 94 96 7B 10 85 C0 74 08 57 56 53 FF D0 }
        $code_128_2 = { 43 00 59 E8 40 02 00 00 68 10 B0 43 00 68 0C B0 }
        $code_192_2 = { 68 00 B0 43 00 E8 F8 01 00 00 83 C4 24 A1 D8 51 }
        $code_224_1 = { 45 9C 50 FF 75 0C FF 75 08 E8 ED 35 00 00 8B 5D }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_080_1 at (pe.entry_point + 80) and $code_224_1 at (pe.entry_point + 224))
                or (pe.imports("wininet.dll", "InternetOpenA") and pe.imports("wininet.dll", "InternetConnectA") and $code_128_2 at (pe.entry_point + 128) and $code_192_2 at (pe.entry_point + 192))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_2 at (pe.entry_point + 16) and $code_128_1 at (pe.entry_point + 128))))
}

rule TrojanDownloader_WinPE_General
{
    meta:
        description = "Static family string cluster for TrojanDownloader_WinPE_General"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = "c:\\users\\george\\desktop\\sal.exe" ascii wide
        $family_2 = "\\notepod.exe" ascii wide
        $family_3 = "=NYcfghew" ascii wide
        $family_4 = "\\sal.exe" ascii wide
        $ep_1 = { 55 8B EC 6A FF 68 88 20 40 00 68 50 18 40 00 64 }
        $ep_2 = { 60 BE 15 B0 40 00 8D BE EB 5F FF FF 57 83 CD FF }
        $code_032_1 = { 53 56 57 89 65 E8 83 65 FC 00 6A 01 FF 15 6C 20 }
        $code_064_1 = { FF FF 15 50 20 40 00 8B 0D F4 3C 40 00 89 08 FF }
        $code_208_2 = { FF FF 5E 89 F7 B9 65 02 00 00 8A 07 47 2C E8 3C }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_208_2 at (pe.entry_point + 208))))
}

rule TrojanDownloader_WinPE_Unruy
{
    meta:
        description = "Static family string cluster for TrojanDownloader_WinPE_Unruy"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "FAILED with delay %d" ascii wide
        $family_2 = "ppIzppozpp(zpp" ascii wide
        $family_3 = "WpJppJhpppJ@J" ascii wide
        $family_4 = "ch:ppGhpp}J" ascii wide
        $ep_1 = { 55 8B EC 6A FF 68 C8 80 40 00 68 AC 58 40 00 64 }
        $ep_3 = { 55 8B EC 83 EC 44 56 FF 15 60 40 40 00 8B F0 8A }
        $code_032_2 = { 53 56 57 89 65 E8 FF 15 64 70 40 00 33 D2 8A D4 }
        $code_064_1 = { 10 F2 41 00 C1 E1 08 03 CA 89 0D 0C F2 41 00 C1 }
        $code_064_3 = { 00 8D 45 BC 50 FF 15 5C 40 40 00 E8 5B 00 00 00 }
        $code_112_2 = { 77 13 00 00 FF 15 60 70 40 00 A3 B4 E2 41 00 E8 }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_2 at (pe.entry_point + 32) and $code_112_2 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))))
}

rule TrojanDownloader_WinPE_VBCode
{
    meta:
        description = "Static family string cluster for TrojanDownloader_WinPE_VBCode"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = ".ISIP^PDXPHMXCMWKYCBEYBWA[QAP@IRF.ISIP^@DXPHMXC%#?)ymj==9o(43&)*7kC( =5<n!-" ascii wide
        $family_2 = "01490.Begin1.17035200.04.02682273.67716009886995Begin9518.223282940.62.704.9.3232364..9529Begin2392002.23.81888983362483" ascii wide
        $family_3 = "234116761714.49644Begin85742.2.61503310.2.08.52.195.4..73004MNQWASMUEWQQKAQ@PYBV>YCY@N@DXPHMXCMWKYCBEYBGMNQWASMUEWQ0MNQW" ascii wide
        $family_4 = "9857617754.1Begin710083412130938139652.332046002946.15Begin6711720860483.720.757763.0563.6709647Begin.135.27641763.43954" ascii wide
        $family_5 = "\\\\\\\\\\\\\\\\\\\\\\\\\\//////\\\\\\/\\/\\/\\/\\\\/\\\\/\\/\\/\\/\\/\\\\/\\/\\/\\/\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\/\\/\\/msvbvm60" ascii wide
        $family_6 = "Begin69.3309724.7745100401.4.1778978.14349Begin67338462642..2586310.521383.485312358Begin83447027787768.2.13337673261057" ascii wide
        $family_7 = "c:\\\\\\\\\\\\/\\/\\/\\/\\//\\\\\\\\\\\\\\\\\\\\\\\\\\\\//////\\\\/\\/\\/windows\\\\\\\\\\\\/\\/\\/\\/\\//\\\\\\\\\\\\\\\\\\\\\\\\\\\\//////\\\\/\\/\\/system32\\\\\\\\\\\\/\\/\\/\\/\\//\\" ascii wide
        $family_8 = "G[ISRUIRWA[QAP@YBV>YCY@N@DXPHMXS]G[ISRUIRWA[QAPPYBV>.4.7973/'?:?$*0,>$RUIRS" ascii wide
        $family_9 = "K@P@YRF.URIP\\PTXPHMXCMWKYCBeYB'o)5 $!IRF/ISI`_PDZPHMFBMWKYCBEYBWA[Q" ascii wide
        $family_10 = "MXCXWKYABEYBGQKAAP@IRF.ISIP^PTH@HMXCMWKYCBEYBGQKQAP@IRF.ISIP^PTHPHMXCMWBa{z" ascii wide
        $family_11 = "XPHXXCMUKYCBEYBGA[QCP@kLF.mkIP}kDXsrMX`wWKFyBEFxWADkAP_sRF1sSIOd@DGiHMC" ascii wide
        $family_12 = "|N\\][l`ddDIDWFTPJB@A_JM]EN@SEN[M\"DCCG^TVSN]IAEOLX@DMCCQKPcrOd~o_q" ascii wide
        $family_13 = "P^jTH@bMXCwWKYyBEYxGQK{AP@sRF.sSIPdPTHzHMXyMWKcCBEcBGQqQAPzIRF" ascii wide
        $family_14 = "PureBasic 5.31 (Windows - x86) - (c) 2014 Fantaisie Software" ascii wide
        $family_15 = "F.I{IP^HTXPxMXCLWkYCBEY\"NA[QAP@IRF.ISIP^PDXPHMXJMWHPCBmQBW" ascii wide
        $family_16 = "P@IRF.ISIP^PDXPHMXCMWKYCBEYBWA[QAP@IRF.ISIP^@DXPHMXCMWKYqB" ascii wide
        $ep_1 = { 7C 90 68 FC 18 40 00 E8 EE FF FF FF 00 00 00 00 }
        $code_032_1 = { 48 8D AA 45 90 18 E4 84 17 D0 5B 09 86 00 00 00 }
        $code_064_1 = { 64 49 6E 00 53 61 6D 70 6C 65 20 41 64 64 49 6E }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule TrojanDropper_WinPE_CoinMiner
{
    meta:
        description = "Static family string cluster for TrojanDropper_WinPE_CoinMiner"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = "7z SFX Constructor v4.6.0.0 (http://usbtor.ru/viewtopic.php?t=798)" ascii wide
        $family_2 = "The archive is corrupted, or invalid password was entered." ascii wide
        $family_3 = "1.6.0 develop [x86] build 2496 (May 28, 2012)" ascii wide
        $family_4 = "InstallPath=\"%Temp%\\\\main\"" ascii wide
        $ep_1 = { 55 8B EC 6A FF 68 80 C4 41 00 68 F0 95 41 00 64 }
        $ep_2 = { E8 9E 03 00 00 E9 8E FE FF FF 55 8B EC 6A 00 FF }
        $code_064_1 = { 00 00 85 C0 74 05 6A 02 59 CD 29 A3 90 A9 45 00 }
        $code_112_1 = { 1D 50 E9 41 00 75 0C 68 E8 95 41 00 FF 15 F0 A1 }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_112_1 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule TrojanDropper_WinPE_FakeOsApp
{
    meta:
        description = "Static family string cluster for TrojanDropper_WinPE_FakeOsApp"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "L%6T.qrk" ascii wide
        $family_2 = "0(d?@?H?P?X?`?h?p?x?" ascii wide
        $family_3 = "K9d?ow`(UTypae" ascii wide
        $family_4 = "P?g?k?o?s?w?{?" ascii wide
        $family_5 = "6f8'h1l^J5xNc" ascii wide
        $family_6 = "sUB1.L1NG]Z" ascii wide
        $family_7 = "V wX?D%Tdp" ascii wide
        $family_8 = "+nt_yrM%y" ascii wide
        $family_9 = ",gdY1cUnN" ascii wide
        $family_10 = "5m:B?PK$P" ascii wide
        $family_11 = "Gk)0(doR2" ascii wide
        $family_12 = "i\\dZ6bSAt" ascii wide
        $family_13 = "sumGv4!-X" ascii wide
        $family_14 = "?d?o%uAV" ascii wide
        $family_15 = "OTx&[s@B" ascii wide
        $family_16 = "zaH/crTH" ascii wide
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
}

rule TrojanDropper_WinPE_Floxif
{
    meta:
        description = "Static family string cluster for TrojanDropper_WinPE_Floxif"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "Az~__GLOBAL_HEAP_S" ascii wide
        $family_2 = "i2222xMor2222~xnn" ascii wide
        $family_3 = "yHDrrrrSLWD2`qry%" ascii wide
        $family_4 = "\",valid 7posi{" ascii wide
        $family_5 = "Unknown excepE" ascii wide
        $family_6 = "_tuv,M''wx<fy" ascii wide
        $family_7 = "vTEaC^RTBByTG" ascii wide
        $family_8 = "out_of_ra&e@" ascii wide
        $family_9 = "s.+8argu(\\{" ascii wide
        $family_10 = "4M(d'uc',K" ascii wide
        $family_11 = "g,,5v27aKl" ascii wide
        $family_12 = "IK@ Cu6DAj" ascii wide
        $family_13 = "4MDLT\\dw" ascii wide
        $family_14 = "EpY1 Evt" ascii wide
        $family_15 = "Snapsho(" ascii wide
        $ep_1 = { 80 7C 24 08 01 0F 85 B9 01 00 00 60 BE 00 00 02 }
        $code_208_1 = { 04 77 F1 01 CF E9 4C FF FF FF 5E 89 F7 B9 42 0C }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_208_1 at (pe.entry_point + 208))))
}

rule TrojanSpy_MSIL_Banker
{
    meta:
        description = "Static family string cluster for TrojanSpy_MSIL_Banker"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_\\-]{27}|mfa\\.[a-zA-Z0-9_\\-]{84}" ascii wide
        $family_2 = "^(?!:\\/\\/)([a-zA-Z0-9-_]+\\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\\.[a-zA-Z]{2,11}?$" ascii wide
        $family_3 = "l|PasswordGenerator.dll|5C407F6F413526440BBBEF311BDECC1E0F41ACF7|14336" ascii wide
        $family_4 = "yToken=null|discord-webhook-client.dll|E9E3D37B08972894F4349CFAA664D84B5F12AEB9|71168" ascii wide
        $family_5 = "BCrypt.BCryptDecrypt() (get size) failed with status code: {0}" ascii wide
        $family_6 = "DotNetZip.dll|1EE724DAAF70C6B0083BF589674B6F6D8427544F|472064" ascii wide
        $family_7 = ":Stealerium.Helpers.GofileFileService+<UploadFileAsync>d__1" ascii wide
        $family_8 = ":Stealerium.Modules.Implant.AntiAnalysis+<HostingAsync>d__4" ascii wide
        $family_9 = ":Stealerium.Target.Messengers.Discord+<TokenStateAsync>d__4" ascii wide
        $family_10 = "Stealer >> Failed recursive remove directory with passwords" ascii wide
        $family_11 = "9Stealerium.Helpers.GofileFileService+<GetServerAsync>d__2" ascii wide
        $family_12 = "^([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$" ascii wide
        $family_13 = "WebcamScreenshot : Camera screenshot failed. (Count {0})" ascii wide
        $family_14 = "6Stealerium.Modules.Implant.AntiAnalysis+<RunAsync>d__8" ascii wide
        $family_15 = "e-me.dll|7A5CB6A163BBE46C0A95DA49B4358156ED6988C4|19968" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule TrojanSpy_MSIL_Formbook
{
    meta:
        description = "Static family string cluster for TrojanSpy_MSIL_Formbook"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "$3a0b1324-2480-4cf7-92fb-fd4bbb1f44f8" ascii wide
        $family_2 = "Cognos 2007-2018" ascii wide
        $family_3 = "Cognos ltd" ascii wide
        $family_4 = "Pong Game" ascii wide
    condition:
        General_WinPE_ValidPE and 2 of ($family_*)
}

rule TrojanSpy_MSIL_QQPass
{
    meta:
        description = "Static family string cluster for TrojanSpy_MSIL_QQPass"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "msg.fcg?clientuin=" ascii wide
        $family_2 = "clientuin=[0-9]*" ascii wide
        $family_3 = "clientkey=\\w*" ascii wide
        $family_4 = "http://203.195.195.219:8080/sys/manage/baseurset.do" ascii wide
        $family_5 = "$96647ea8-5059-48cf-9914-c860800729d8" ascii wide
        $family_6 = "the mlen > slen" ascii wide
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
}

rule TrojanSpy_MSIL_RedLine
{
    meta:
        description = "Static family string cluster for TrojanSpy_MSIL_RedLine"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "http://bot.whatismyipaddress.com/" ascii wide
        $family_2 = "https://wtfismyip.com/text" ascii wide
        $family_3 = "http://checkip.dyndns.org" ascii wide
        $family_4 = "; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/CommandLine" ascii wide
        $family_5 = "^3(?:0[0-5]|[68][0-9])[0-9]{11}$\\NVIDIA Corporation\\NVIDIA GeForce Experience" ascii wide
        $family_6 = "\\Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewerCookies" ascii wide
        $family_7 = "10[0-9]{12}|633110[0-9]{13}$\\NETGATE Technologies\\BlackHaw" ascii wide
        $family_8 = "\\Comodo\\Dragon\\User Data\\360Browser\\Browser\\User Data" ascii wide
        $family_9 = "host_key^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$" ascii wide
        $family_10 = "\\Torch\\User Data\\CatalinaGroup\\Citrio\\User Data" ascii wide
        $family_11 = "5[1-5][0-9]{14}$\\Google(x86)\\Chrome\\User Data" ascii wide
        $family_12 = "ovpn\\BraveSoftware\\Brave-Browser\\User Data" ascii wide
        $family_13 = "ttp://checkip.amazonaws.com/Mozilla/5.0 (" ascii wide
        $family_14 = "\\Google\\Chrome\\User DataKoreanLocalCard" ascii wide
        $code_080_1 = { 64 00 6F 00 5C 00 55 00 73 00 65 00 72 00 20 00 }
        $code_160_1 = { 6C 00 65 00 73 00 54 00 6F 00 74 00 61 00 6C 00 }
        $code_160_2 = { 70 00 70 00 44 00 61 00 74 00 61 00 5C 00 4C 00 }
        $code_224_2 = { 02 01 04 03 02 05 01 02 00 00 00 00 00 00 5B 00 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.data_directories[14].size > 0 and $code_080_1 at (pe.entry_point + 80) and $code_160_1 at (pe.entry_point + 160))
                or (pe.data_directories[14].size > 0 and $code_160_2 at (pe.entry_point + 160) and $code_224_2 at (pe.entry_point + 224))))
}

rule TrojanSpy_MSIL_SnakeKeylogger
{
    meta:
        description = "Static family string cluster for TrojanSpy_MSIL_SnakeKeylogger"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "CEnterprise server infrastructure management and monitoring platform" ascii wide
        $family_2 = "Enterprise server infrastructure management and monitoring platform" ascii wide
        $family_3 = "$B3F8A7C6-D5E4-9283-A176-543E87D92C1F" ascii wide
        $family_4 = "ServerOps Console Enterprise" ascii wide
        $family_5 = "InitializeProcessingSystem" ascii wide
        $family_6 = "MAX_CONCURRENT_CONNECTIONS" ascii wide
        $family_7 = "InfraCore Systems 2025" ascii wide
        $family_8 = "InfraCore Systems" ascii wide
        $family_9 = "ServerOps Console" ascii wide
        $family_10 = "Software Mercadin" ascii wide
        $family_11 = "Inserir Produto" ascii wide
        $family_12 = "TOTAL DA VENDA" ascii wide
        $family_13 = "Nome Produto" ascii wide
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
}

rule TrojanSpy_Win64_Ursnif
{
    meta:
        description = "Static family string cluster for TrojanSpy_Win64_Ursnif"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "D$XL!\\$0L!\\$`L!\\$hL!\\$xL!" ascii wide
        $family_2 = "L9\\$8s!D!l$(L!l$ E3" ascii wide
        $family_3 = "D$Z9T$xtb9T$|t\\H" ascii wide
        $family_4 = "!t$(H!t$ Hi" ascii wide
        $family_5 = "A3\\$PE3\\$XD" ascii wide
        $family_6 = "t=HcT$lH" ascii wide
        $family_7 = "tcH!l$ L" ascii wide
        $family_8 = "th9{X}RL" ascii wide
        $family_9 = "tQH9k(uK" ascii wide
        $family_10 = "u+9sLu&H" ascii wide
        $ep_1 = { 40 53 48 83 EC 20 BB 01 00 00 00 85 D2 74 24 3B }
        $code_032_1 = { C3 75 1F 49 8B D0 E8 49 D6 FD FF 85 C0 74 13 33 }
        $code_064_1 = { FF FF 8B C3 48 83 C4 20 5B C3 FF 25 28 42 00 00 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule TrojanSpy_WinPE_CosmicDuke
{
    meta:
        description = "Static family string cluster for TrojanSpy_WinPE_CosmicDuke"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "8ABCDEFGHIJKLMNO|PQRSTUVWXYZ[\\]^_`ABCDEFGHIJKLMNO" ascii wide
        $family_2 = "3 4%4+4/45494?4C4I4M4R4X4\\4b4f4l4p4v4z4X5" ascii wide
        $family_3 = "Labe2869f-9b47-4cd9-a358-c22904dba7f7" ascii wide
        $family_4 = "R$dD:\\SVA\\NITRO\\BotGenStudio\\" ascii wide
        $family_5 = "H`local static thread guard'" ascii wide
        $family_6 = "`ions\\80051A85\\bin\\bot.pdb>" ascii wide
        $family_7 = "d\"%SYSTEMROOT%\\system32\\cmd" ascii wide
        $family_8 = "`select id, hostname, user" ascii wide
        $family_9 = "r{4CB43D7F-7DCA-4906-8698-" ascii wide
        $family_10 = "3 3(30383@3H3P3X3`3h3p3xM" ascii wide
        $family_11 = "9%90959;9J9Q9Y9_9e9k9q9w9" ascii wide
        $family_12 = "*\\.?AVaccess_violation@@" ascii wide
        $ep_1 = { E8 FF 20 00 00 E9 89 FE FF FF E8 A2 24 00 00 85 }
        $ep_2 = { 56 E8 83 00 00 00 8B F0 E8 48 00 00 00 68 04 30 }
        $code_032_1 = { 00 02 74 11 6A 01 68 15 00 00 40 6A 03 E8 7C 21 }
        $code_064_1 = { 8B EC 8B 4D 0C A1 7C A0 42 00 8B 55 08 23 55 0C }
        $code_064_2 = { 3B 74 24 0C 73 0D 8B 06 85 C0 74 02 FF D0 83 C6 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("advapi32.dll", "OpenSCManagerW") and pe.imports("advapi32.dll", "CreateServiceW") and $ep_2 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))))
}

rule TrojanSpy_WinPE_GameteaSpy
{
    meta:
        description = "Static family string cluster for TrojanSpy_WinPE_GameteaSpy"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "gkq@lwf3" ascii wide
        $family_2 = "Z9Ol7XF=" ascii wide
        $family_3 = "C:\\oK695SRY.exC:\\9QzqOBzT.exe" ascii wide
        $family_4 = "C:\\00XwNNHE.exe" ascii wide
        $family_5 = "C:\\06uOqc8Z.exe" ascii wide
        $family_6 = "C:\\0_U6nbZL.exe" ascii wide
        $family_7 = "C:\\0b9nO23A.exe" ascii wide
        $family_8 = "C:\\0bh_rKvI.exe" ascii wide
        $family_9 = "C:\\0BVRlA7t.exe" ascii wide
        $family_10 = "C:\\0dDbnYcd.exe" ascii wide
        $family_11 = "C:\\0EcqgB79.exe" ascii wide
        $family_12 = "C:\\0fx52gUc.exe" ascii wide
        $family_13 = "C:\\0gUtBcgU.exe" ascii wide
        $family_14 = "C:\\0gZQuPBx.exe" ascii wide
        $family_15 = "C:\\0h4MavYM.exe" ascii wide
        $family_16 = "C:\\0HjDA9Ah.exe" ascii wide
        $ep_2 = { E8 8B 12 00 00 E8 B3 11 00 00 33 C0 C3 90 90 90 }
        $ep_3 = { E8 4F 19 00 00 68 2F A9 A7 8F 8D 64 24 24 0F 87 }
        $code_064_1 = { 04 A9 00 01 01 81 74 E8 8B 41 FC 84 C0 74 26 84 }
        $code_064_2 = { 00 CD FD 6E BF F4 CD 80 39 46 35 21 1D E7 6D AE }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_2 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))))
}

rule TrojanSpy_WinPE_Golf
{
    meta:
        description = "Static family string cluster for TrojanSpy_WinPE_Golf"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "\\Program Files\\naver\\NaverAgent\\NaverAgent.exe" ascii wide
        $family_2 = "\\Program Files\\AhnLab\\V3Lite30\\V3Lite.exe" ascii wide
        $family_3 = "\\Program Files\\ESTsoft\\ALYac\\AYLaunch.exe" ascii wide
        $family_4 = "\\Netmarble\\Common\\NetMarbleEndWeb.exe" ascii wide
        $family_5 = "\\NEOWIZ\\PMang\\common\\PMLauncher.exe" ascii wide
        $family_6 = "\\Hangame\\KOREAN\\HanUninstall.exe" ascii wide
        $ep_4 = { E8 19 69 00 00 E9 17 FE FF FF 55 8B EC 81 EC 28 }
        $code_032_1 = { 01 83 C1 02 66 85 C0 75 F5 66 8B 45 0C 83 E9 02 }
        $code_048_2 = { 74 02 33 C0 5D C3 8B FF 55 8B EC 8B 45 08 53 8B }
        $code_096_1 = { 02 8D 42 01 A8 0E 75 E7 33 C0 66 3B C1 75 1F B8 }
        $code_112_2 = { DA 75 08 41 41 66 39 1C 08 75 E5 66 83 39 00 74 }
        $code_240_3 = { 75 08 6A 01 E8 B9 68 00 00 59 68 09 04 00 C0 FF }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("ws2_32.dll", "WSAStartup") and pe.imports("ws2_32.dll", "connect") and $code_032_1 at (pe.entry_point + 32) and $code_096_1 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_048_2 at (pe.entry_point + 48) and $code_112_2 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_240_3 at (pe.entry_point + 240))))
}

rule TrojanSpy_WinPE_Keylogger
{
    meta:
        description = "Static family string cluster for TrojanSpy_WinPE_Keylogger"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = "\\RollerCoaster Tycoon NO CD Crack (Including Attractions Pack).exe" ascii wide
        $family_2 = "\\Sponge Bob Square Pants - Operation Krabby Patty no cd crack.exe" ascii wide
        $family_3 = "\\Star Wars Galactic Battlegrounds- Clone Campaigns no cd crack.exe" ascii wide
        $family_4 = "\\Ad-Aware SE Enterprise Edition 2005 v1.5 Serial_and_Crack.exe" ascii wide
        $family_5 = "Klasse %s nicht gefunden/Liste gestattet keine doppelten Eintr" ascii wide
        $family_6 = "%s:Ein Aufruf einer Betriebssystemfunktion ist fehlgeschlagen" ascii wide
        $family_7 = "\\Medal Of Honor - Allied Assault BreakThrough no cd crack.exe" ascii wide
        $family_8 = "Dateizugriff verweigert%Versuch hinter dem Dateiende zu lesen" ascii wide
        $family_9 = "ltige Variant-Operation(Variant-Methodenaufruf nicht unterst" ascii wide
        $family_10 = "\\ADAC Tourenplaner 2006-2007 Deutschland-Europa-CRACK.exe" ascii wide
        $family_11 = "\\Dark Age Of Camelot - Trials Of Atlantis no cd crack.exe" ascii wide
        $family_12 = "\\Star Wars Jedi Knight II - Jedi Outcast no cd crack.exe" ascii wide
        $family_13 = "\\Command & Conquer - Generals Zero Hour no cd crack.exe" ascii wide
        $family_14 = "\\Star Wars - Jedi Knight - Jedi Academy no cd crack.exe" ascii wide
        $family_15 = "\\Star Wars Jedi Knight II- Jedi Outcast no cd crack.exe" ascii wide
        $family_16 = "\\Tom Clancys Ghost Recon - Desert Siege no cd crack.exe" ascii wide
        $ep_1 = { 55 8B EC B9 18 00 00 00 6A 00 6A 00 49 75 F9 51 }
        $ep_2 = { E8 CE 02 00 00 E9 7A FE FF FF 55 8B EC 51 83 3D }
        $code_032_1 = { 41 00 64 FF 30 64 89 20 8D 45 EC E8 E8 EB FF FF }
        $code_064_1 = { B8 01 00 00 00 E8 D2 4A FE FF 8B 45 E8 BA 14 EF }
        $code_128_2 = { C9 C3 55 8B EC FF 75 08 E8 0A 00 00 00 F7 D8 59 }
    condition:
        ((General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_128_2 at (pe.entry_point + 128))))) and
        (2 of ($family_1, $family_2, $family_3, $family_4, $family_7, $family_10, $family_11, $family_12, $family_13, $family_14, $family_15, $family_16))
}

rule TrojanSpy_WinPE_RedLine
{
    meta:
        description = "Static family string cluster for TrojanSpy_WinPE_RedLine"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "ScanChromeBrowsersPaths\"" ascii wide
        $family_2 = "profiles\\Windows\\" ascii wide
        $family_3 = "%USERPstring.ReplaceROFILE%\\Apstring.ReplacepData\\Locastring.Replacel" ascii wide
        $family_4 = "[AString-ZaString-z\\d]{2String4}\\.[String\\w-]{String6}\\.[\\wString-]{2String7}" ascii wide
        $family_5 = "%USERPEnvironmentROFILE%\\AppDEnvironmentata\\RoaEnvironmentming" ascii wide
        $family_6 = ", Name: AppData\\Roaming\\TReplaceokReplaceenReplaces.tReplacext" ascii wide
        $family_7 = "%USERPFile.WriteROFILE%\\AppFile.WriteData\\RoamiFile.Writeng" ascii wide
        $family_8 = "%USEWanaLifeRPROFILE%\\AppDaWanaLifeta\\LWanaLifeocal" ascii wide
        $family_9 = "<GetWindowsVersion>g__HKLM_GetString|11_0" ascii wide
        $family_10 = "%appdata%\\discord\\Local Storage\\leveldb" ascii wide
        $family_11 = "\\EtFile.IOhereuFile.IOm\\walFile.IOlets" ascii wide
        $family_12 = "*.vstring.Replacedf" ascii wide
        $family_13 = "Yandex\\YaAddon" ascii wide
        $code_016_1 = { 69 00 6C 00 6C 00 35 00 74 00 59 00 57 00 52 00 }
        $code_080_2 = { 73 00 5A 00 58 00 51 00 4B 00 61 00 57 00 4A 00 }
        $code_096_1 = { 6C 00 65 00 73 00 54 00 6F 00 74 00 61 00 6C 00 }
        $code_112_3 = { 65 00 63 00 74 00 69 00 6F 00 6E 00 6F 00 69 00 }
        $code_176_1 = { 55 00 53 00 45 00 52 00 50 00 45 00 6E 00 76 00 }
        $code_192_3 = { 20 00 6F 00 66 00 20 00 52 00 41 00 4D 00 68 00 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.data_directories[14].size > 0 and $code_096_1 at (pe.entry_point + 96) and $code_176_1 at (pe.entry_point + 176))
                or (pe.data_directories[14].size > 0 and $code_112_3 at (pe.entry_point + 112) and $code_192_3 at (pe.entry_point + 192))
                or (pe.data_directories[14].size > 0 and $code_016_1 at (pe.entry_point + 16) and $code_080_2 at (pe.entry_point + 80))))
}

rule TrojanSpy_WinPE_Rhadamanthys
{
    meta:
        description = "Static family string cluster for TrojanSpy_WinPE_Rhadamanthys"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "! U R.L J.D.Y.J*.A l_b.R_m.5 S_l.eO~*eg f.H.5.4_mo.r g_d j_n_k(/_u.g Qt H.J_w g.w~.V.A.E_C_q_I" ascii wide
        $family_2 = "! U> l?.A q_I qv.I.3.79.p;.Q_p.j_u b.Z ZP_R_Ht_W.m~_Z.Q.yi4# pd.Z9 f_T K_o} T.MR Q} NW x" ascii wide
        $family_3 = "! Y jp s.2%& B:.eY.n_k* I R.4.v.h.rn_D0 c.H\\_f+z.e JN0@.7 meG@&A_y.c_s?r.x.Z.nk_S-.G3.v" ascii wide
        $family_4 = "!.1 U_D.a.5).5K_V_v2.TE l3: F_dL_Vx.0.L_p Q K[LlSjdV.2PV I~.jU.s.u<_v.1.ai_l" ascii wide
        $family_5 = "!].J n2} d_J.o.5 r_D.tA.Zf_I_J]9 gf.Ktj7.h_v`.q U.y d.X xk^b\\ y z_C" ascii wide
        $family_6 = "!_v_k.X_FJ5t.p.y/.o~ e.aP.U_o.vPY_K W^=.E u.O K.j_x.7.3.hj.rZh/ pw_y p.bI q.m.S.W_o( z_" ascii wide
        $family_7 = "# D V_k.m.7W_G.5vO.V_H.l@.1y.b_eu.T/_cJVs_H D_Nn_y sQk_N.5 S J.7 R" ascii wide
        $family_8 = "#.h3.a_D Z z.E_l Mp_i_c_h_w*.V.k&].bD`_l b Oo.FX.q_f_Iy_a; k_W.A" ascii wide
        $family_9 = "#< Y.O O.F4_j_x c.smz.s m s Qg.2_v.0_qG_Gv-[[_C_i Y.5_i.i_b.8M_Ol F.4.Y_y.W.bdB_Q.3_I H_O_H." ascii wide
        $family_10 = "$ O!_GH_c I_H t v r=ArfAF o_p n}_s.oJ_cG w.h l_kN.P.P_x.O w_u[ Y_PS T_J.Zm.r.g.9" ascii wide
        $family_11 = "$,5_Zo Y_j.z.d.d} c.SJO_O.x_G R Xjh I.W.F0 hk&.YasO6j m_C q I.h X t" ascii wide
        $family_12 = "$_b_Y RA_Vr{ hKW~_IlY.b: w oP A.h iGfs_VM A_a>_ytR.c~_H_S|y.1_YD_B^ a88" ascii wide
        $family_13 = "$iLga_L F.S.L.qH!_ll_v< S_Q.T.8_n.C Zc.Z b S.C_P g j1p+ l g.bM E lz," ascii wide
        $family_14 = "$N_e.Z.gm s_M_yE.e_TZ)C.o5 S cY_G D B.4 r.J.v.B.OBO.K_X Z_Q.e w_q HI.V D." ascii wide
        $family_15 = "$Q.r.w_C.X.Q.A c U_RQ i~A K k_x.V_G N.x.CWi MU~#_s.o.I_a o O xw.F.3 j t_b_A_G.P.i~x.N" ascii wide
        $family_16 = "%_H_F i.C k.S.G pw_f] m.d.lp G M E_Pf P Y.i[_m.YV]_Q.Ge.HVJa_f_R.K_E.N(.9=.O_j.5M{t." ascii wide
        $code_080_1 = { 55 53 48 83 EC 78 48 8D 6C 24 70 48 89 4D 20 48 }
        $code_080_2 = { 55 57 56 53 48 81 EC 38 02 00 00 48 8D AC 24 80 }
        $code_144_1 = { E7 48 89 C1 E8 D7 32 03 00 90 48 8D 45 C0 48 89 }
        $code_144_2 = { 97 01 00 00 48 89 95 98 01 00 00 90 90 4C 8D 85 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_080_1 at (pe.entry_point + 80) and $code_144_1 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_080_2 at (pe.entry_point + 80) and $code_144_2 at (pe.entry_point + 144))))
}

rule TrojanSpy_WinPE_Socelars
{
    meta:
        description = "Static family string cluster for TrojanSpy_WinPE_Socelars"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0) Gecko/20100101 Firefox/6.0" ascii wide
        $family_2 = "SELECT host,name,value,expiry FROM moz_cookies where host='" ascii wide
        $family_3 = "SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallWhitelist" ascii wide
        $family_4 = "select * from logins where blacklisted_by_user=0" ascii wide
        $ep_1 = { E8 99 04 00 00 E9 74 FE FF FF 83 61 04 00 8B C1 }
        $ep_2 = { E8 F5 04 00 00 E9 74 FE FF FF 55 8B EC 56 FF 75 }
        $code_096_1 = { 4E 00 64 FF 35 00 00 00 00 8B 44 24 10 89 6C 24 }
        $code_112_2 = { 8D 41 04 C7 01 F0 E4 50 00 50 E8 54 24 00 00 59 }
    condition:
        ((General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_096_1 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_112_2 at (pe.entry_point + 112))))) and
        ($family_2 and $family_3 and $family_4)
}

rule Trojan_BAT_Decertuil
{
    meta:
        description = "Static family string cluster for Trojan_BAT_Decertuil"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples containing batch-script artifacts or payloads; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = ":&:=:C:I:O:U:[:b:i:p:w:~:" ascii wide
        $family_2 = "7'717=7C7J7S7Y7a7g7t7|7" ascii wide
        $family_3 = "='=A=H=M=R=W=\\=a=f=l=z=" ascii wide
        $family_4 = "?,?1?8???G?R?W?_?e?r?" ascii wide
        $family_5 = "7 7)7A7J7O7U7[7e7k7" ascii wide
        $family_6 = "8!8'828C8K8U8d8j8r8" ascii wide
        $family_7 = "8,8D8L8T8]8b8x8" ascii wide
        $family_8 = "6 6A6K6Z6a6r6" ascii wide
        $family_9 = "ust specify a folder with fully qualified pathname or choose Cancel.U" ascii wide
        $family_10 = "Command /?." ascii wide
        $code_016_1 = { 58 68 68 75 40 00 E8 BD 0B 00 00 33 DB 89 5D E0 }
        $code_096_1 = { F0 88 40 00 01 75 17 6A 1F E8 30 09 00 00 59 EB }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_096_1 at (pe.entry_point + 96))))
}

rule Trojan_BAT_Disabler
{
    meta:
        description = "Static family string cluster for Trojan_BAT_Disabler"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples containing batch-script artifacts or payloads; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "5 5$5(5,5054585<5@5D5H5L5P5T5X5@7D7" ascii wide
        $family_2 = "5 5$5,5054585<5@5D5H5T5\\5`5d5h5l5" ascii wide
        $family_3 = "8 8'8.858<8H8O8V8]8e8l8s8z8\\:c:o:" ascii wide
        $family_4 = "C<pi-ms-win-core-fibers-l1-1-1" ascii wide
    condition:
        General_WinPE_AnySizePE and 2 of ($family_*)
}

rule Trojan_BAT_KillAV
{
    meta:
        description = "Defender Remover embedded script and package markers"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples containing batch-script artifacts or payloads; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
        confidence = "high"
        refinement = "requires family-specific remover/package anchors; generic archive error messages excluded"
    strings:
        $anchor_1 = ";copy /b compiler.mpm + config.txt + drv.7z gallery_mpm.mpm;" ascii wide
        $anchor_2 = "Title=\"Defender Remover Setup\"" ascii wide
        $anchor_3 = "RunProgram=\"Script_Run.bat\"" ascii wide
    condition:
        General_WinPE_ValidPE and 2 of ($anchor_*)
}

rule Trojan_BAT_Maloader
{
    meta:
        description = "Static family string cluster for Trojan_BAT_Maloader"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples containing batch-script artifacts or payloads; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
        confidence = "high"
    strings:
        $family_1 = "qX:FfPV3=aiK" ascii wide
        $family_2 = "+Clz/K0sI%G" ascii wide
        $family_3 = "DG){cvYFnI" ascii wide
        $family_4 = "p[fTXSQ,X/" ascii wide
        $family_5 = "2Dipn%wjd" ascii wide
        $family_6 = "=ochC{LT@" ascii wide
        $family_7 = "GrJvz,sZR" ascii wide
        $family_8 = "L:JU]fLA_" ascii wide
        $family_9 = "Q}::KndSE" ascii wide
        $family_10 = "(na=?eXM" ascii wide
        $family_11 = "A5N0M)YK" ascii wide
        $family_12 = "Ko[!of@v" ascii wide
        $family_13 = "n-6%ImwD" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule Trojan_JS_Injector
{
    meta:
        description = "Self-extracting archive with embedded JScript launcher"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples containing JavaScript artifacts or payloads; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
        confidence = "high"
        refinement = "requires the JScript execution command plus archive context"
    strings:
        $family_1 = ") & (start /MIN wscript.exe /E:jscript 4157934657 188 \"%sfxname%\")" ascii wide
        $family_2 = "AYou may need to run this self-extracting archive as administrator" ascii wide
        $family_3 = "Unknown encryption method in %s$The specified password is incorrect." ascii wide
        $family_4 = "Checksum error in %s Packed data checksum error in %s" ascii wide
        $family_5 = "2created automatically before extraction.</li></ul>" ascii wide
        $family_6 = "2The archive is either in unknown format or damaged" ascii wide
        $family_7 = "<$=3=7=;=?=C=G=K=O=S=W=[=_=c=g=k=o=s=w={=" ascii wide
        $family_8 = "%The archive comment header is corrupt" ascii wide
        $family_9 = "The file \"%s\" header is corrupt" ascii wide
        $family_10 = "Main archive header is corrupt" ascii wide
        $family_11 = "The required volume is absent" ascii wide
    condition:
        General_WinPE_ValidPE and
        $family_1 and 3 of ($family_*)
}

rule Trojan_MSIL_Agensla
{
    meta:
        description = "Static family string cluster for Trojan_MSIL_Agensla"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "$ff618bbc-cc13-4cb1-bad4-8b3604d989d7" ascii wide
        $family_2 = "pictureBox1.BackgroundImage" ascii wide
        $family_3 = "Ginger Grammer Checker" ascii wide
        $family_4 = "Gb$mKJ/n" ascii wide
        $family_5 = "vPvdhT=," ascii wide
    condition:
        General_WinPE_ValidPE and 2 of ($family_*)
}

rule Trojan_MSIL_CoinStealer
{
    meta:
        description = "Static family string cluster for Trojan_MSIL_CoinStealer"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = "\\LitecoinCore\\wallet.dat" ascii wide
        $family_2 = "\\BitcoinCore\\wallet.dat" ascii wide
        $family_3 = "\\DashCore\\wallet.dat" ascii wide
        $family_4 = "\\wallet.dat" ascii wide
        $family_5 = "\\Bytecoin\\" ascii wide
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
}

rule Trojan_MSIL_DDos
{
    meta:
        description = "Static family string cluster for Trojan_MSIL_DDos"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
        confidence = "high"
    strings:
        $family_1 = "\\Log.tmp" ascii wide
        $family_2 = "/create /f /RL HIGHEST /sc minute /mo 1 /tn \"" ascii wide
        $family_3 = "/create /f /sc minute /mo 1 /tn \"" ascii wide
        $family_4 = "/delete /f  /tn \"" ascii wide
        $family_5 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionProcess '" ascii wide
        $family_6 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionPath '" ascii wide
        $family_7 = "\\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{26,45}\\b" ascii wide
        $family_8 = "\\b(0x)[a-zA-HJ-NP-Z0-9]{40,45}\\b" ascii wide
        $family_9 = "T[A-Za-z1-9]{33}" ascii wide
        $family_10 = "TRC20 Clipper" ascii wide
        $family_11 = "BTC Clipper" ascii wide
        $family_12 = "ETH Clipper" ascii wide
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*)) and
        (pe.data_directories[14].size > 0 and 1 of ($family_2, $family_3) and 1 of ($family_5, $family_6) and 1 of ($family_10, $family_11, $family_12) and 1 of ($family_7, $family_8, $family_9))
}

rule Trojan_Win64_CoinMiner
{
    meta:
        description = "Static family string cluster for Trojan_Win64_CoinMiner"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = "SchnBuberhfo[XlW" ascii wide
        $family_2 = "9Process;Moduhu" ascii wide
        $family_3 = "m,bN:NX:,o" ascii wide
        $family_4 = "O@_TEXT_CN" ascii wide
        $family_5 = "Bh!\\ZLsT" ascii wide
        $family_6 = "NNNN $(,NNNN69;=NNNN@DHLNNNNVY[]NNNN`dhlNNNNvy{}NNNN" ascii wide
        $ep_2 = { 70 79 9F 60 FF 1D DC 86 49 14 72 55 4F FB FA 87 }
        $ep_3 = { 4D 73 56 66 71 72 6C 42 53 73 79 6E 4B 68 61 4A }
        $code_032_1 = { 15 E7 6A 08 00 48 8B CB FF 15 D6 6A 08 00 FF 15 }
        $code_064_2 = { EF CD 14 2E 77 76 A5 0C D3 6B C0 43 81 0D 57 61 }
        $code_064_3 = { 50 79 54 63 72 55 64 75 62 7A 69 47 43 5A 71 7A }
        $code_096_1 = { 02 00 00 00 CD 29 48 8D 0D EF 12 0C 00 E8 CA 01 }
        $code_112_1 = { 83 EC 18 C7 04 24 F4 FF FF FF 54 5D FF 15 50 50 }
        $code_176_1 = { FF 15 14 50 6E 00 55 5E 83 C4 18 C3 CC CC CC CC }
        $code_176_2 = { FF 15 14 50 6E 00 89 EE 83 C4 18 C3 CC CC CC CC }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_112_1 at (pe.entry_point + 112) and $code_176_2 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_112_1 at (pe.entry_point + 112) and $code_176_1 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_1 at (pe.entry_point + 32) and $code_096_1 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))))
}

rule Trojan_Win64_Dridex
{
    meta:
        description = "Static family string cluster for Trojan_Win64_Dridex"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "importanthentaiIlifehack39performance.57Rversionm" ascii wide
        $family_2 = "2009,mupdatescongratulatedbutton6toUcalled3" ascii wide
        $family_3 = "Vn2015.188RSquirrelFishChromescriptedwolf" ascii wide
        $family_4 = "VLincludedtheReleaseand32009,bereceiving" ascii wide
        $family_5 = "5removedG5seekw132cfeaturesrearranged," ascii wide
        $family_6 = "2xmouse-clicking5Chromerthoughmeaning" ascii wide
        $family_7 = "sdyGallery).162uaboutbluearefirstl" ascii wide
        $family_8 = "7.5.7600.16385 (win7_rtm.090713-" ascii wide
        $family_9 = "Explorer3,Nowhenfxoffnotrainbowc" ascii wide
        $family_10 = "mz2015.188aMincludesannouncedC" ascii wide
        $family_11 = "vusagexsChrome,fmajorwithyv" ascii wide
        $family_12 = "xyankeeaseYpreviouslyxnez" ascii wide
        $family_13 = "becauseklocalupTamarin)" ascii wide
        $family_14 = "jJIhomevinprince14," ascii wide
        $ep_1 = { 48 31 C0 48 83 C0 5A 48 89 0D 82 3D 07 00 48 8D }
        $ep_2 = { 31 D0 EB 08 41 59 49 83 C1 08 FF D7 57 48 8B 3D }
        $code_032_1 = { 89 0D 92 3D 07 00 4C 89 2D A3 3D 07 00 4C 89 05 }
        $code_064_1 = { 07 00 4C 89 25 8F 3D 07 00 48 89 C1 48 83 E9 5A }
        $code_080_2 = { 53 57 56 48 81 EC D0 00 00 00 B8 5F D4 9A 91 41 }
        $code_112_2 = { 80 44 8B 8C 24 C8 00 00 00 44 29 C8 89 84 24 C8 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))
                or ($ep_2 at (pe.entry_point + 0) and $code_080_2 at (pe.entry_point + 80) and $code_112_2 at (pe.entry_point + 112))))
}

rule Trojan_WinPE_Antavmu
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_Antavmu"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "$TMP!10@.COM" ascii wide
        $family_2 = "%u%u.exe" ascii wide
        $family_3 = "9C:N:z::?v:g:m:+=" ascii wide
        $family_4 = "3%363B3K3a3s3z3" ascii wide
        $ep_1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 28 F1 }
        $code_064_1 = { 59 68 C4 F0 40 00 6A 00 E8 35 D6 00 00 A3 23 F1 }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Trojan_WinPE_AuthBypass
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_AuthBypass"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = "<source location=\"%configsetroot%\\Windows6.0-KB929761-x86.CAB\" />" ascii wide
        $family_2 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" ascii wide
        $family_3 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\AddIns\\Dynamic VC" ascii wide
        $family_4 = "SYSTEM\\CurrentControlSet\\ControlTerminal Server\\AddIns\\Clip Redirector" ascii wide
        $family_5 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Licensing Core" ascii wide
        $family_6 = "C:\\Users\\louis\\Documents\\workspace\\MortyCrypter\\MsgBox.exe" ascii wide
        $family_7 = "SYSTEM\\CurrentControlSet\\Services\\TermService\\Parameters" ascii wide
        $family_8 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\AddIns" ascii wide
        $family_9 = "An assertion condition failed" ascii wide
        $family_10 = "/n:%temp%\\ellocnak.xml" ascii wide
        $family_11 = "-w %ws -d C -f %s" ascii wide
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
}

rule Trojan_WinPE_BumbleBee
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_BumbleBee"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "C:\\Windows\\System32\\msimg32.TransparentBlt" ascii wide
        $family_2 = "C:\\Windows\\System32\\msimg32.DllInitialize" ascii wide
        $family_3 = "C:\\Windows\\System32\\msimg32.vSetDdrawflag" ascii wide
        $family_4 = "C:\\Windows\\System32\\msimg32.GradientFill" ascii wide
        $family_5 = "C:\\Windows\\System32\\msimg32.AlphaBlend" ascii wide
    condition:
        General_WinPE_ValidPE and 2 of ($family_*)
}

rule Trojan_WinPE_Delf
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_Delf"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = "wfOC|xswniG_hlmEOVuAWUNGGvnT]B@BT@ouQ@VVZ__" ascii wide
        $family_2 = "Transfer Server. Compiled : 2004/02/15" ascii wide
        $family_3 = "Command Server. Compiled : 2004/02/15" ascii wide
        $family_4 = ".0.17134.1304\"System Default Context" ascii wide
        $family_5 = ".0.7600.16385\"System Default Context" ascii wide
        $family_6 = "C:\\Windows\\system32\\comctl32.dll.mui" ascii wide
        $family_7 = "C:\\Windows\\SysWOW64\\comctl32.dll.mui" ascii wide
        $family_8 = ".0.18362.657\"System Default Context" ascii wide
        $family_9 = ".1.2600.2000\"System Default Context" ascii wide
        $family_10 = "$ucnB1r6rudYgICAgZ2xqZ0BtYWNkLmNu$" ascii wide
        $family_11 = ".0.15063.0\"System Default Context" ascii wide
        $family_12 = ".0.19041.1\"System Default Context" ascii wide
        $family_13 = "C:\\Windows\\system32\\comctl32.dll" ascii wide
        $family_14 = "C:\\Windows\\SysWOW64\\comctl32.dll" ascii wide
        $family_15 = "C:\\WINDOWS\\system32\\GdiPlus.dll" ascii wide
        $family_16 = "C:\\Windows\\system32\\GdiPlus.dll" ascii wide
        $ep_2 = { 55 8B EC 83 C4 F0 B8 E8 89 47 00 E8 14 D9 F8 FF }
        $code_016_1 = { 56 B8 F8 8F 41 00 E8 59 D3 FE FF 33 C0 55 68 B5 }
        $code_064_2 = { E8 FB 1E FE FF A1 18 AD 47 00 8B 00 E8 6F 1F FE }
        $code_080_1 = { 8D 55 E8 B8 CC 92 41 00 E8 E7 E4 FF FF 8B 55 E8 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("wsock32.dll", "WSAStartup") and pe.imports("wsock32.dll", "connect") and $code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))))
}

rule Trojan_WinPE_Diofopi
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_Diofopi"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "Create Child Cmd.exe Process Succeed!" ascii wide
        $family_2 = "/c ping 127.0.0.1 & del /q \"%s\"" ascii wide
        $family_3 = "0 2O2t2W4S6W6[6_6c6g6k6o6|6" ascii wide
        $family_4 = "wlgVAEPAmPAIbVKItEVWMJCjEIA" ascii wide
        $family_5 = "@%bVAAhMFVEV]eJ@a\\MPpLVAE@" ascii wide
        $family_6 = "6$61666<6E6N6V6a6f6k6p6z6" ascii wide
        $family_7 = "Child ProcessId is %d" ascii wide
        $family_8 = "0&cAPiK@QHAbMHAjEIAe" ascii wide
        $family_9 = "1&cAPiK@QHAbMHAjEIAs" ascii wide
        $family_10 = "?resid=%d&photoid=" ascii wide
        $family_11 = "Self Process Id:%d" ascii wide
        $family_12 = "6P7V7\\7b7h7n7u7|7" ascii wide
        $ep_1 = { E8 D2 57 00 00 E9 78 FE FF FF 8B FF 55 8B EC 81 }
        $code_064_1 = { 8C 0D 54 3B 41 00 66 8C 1D 30 3B 41 00 66 8C 05 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Trojan_WinPE_Glupteba
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_Glupteba"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 8B FF 55 8B EC E8 A6 86 00 00 E8 11 00 00 00 5D }
        $ep_2 = { E8 AD 81 00 00 E9 78 FE FF FF 8B 4C 24 04 F7 C1 }
        $ep_3 = { 8B FF 55 8B EC E8 46 AA 00 00 E8 11 00 00 00 5D }
        $code_064_1 = { 12 43 00 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 }
        $code_064_2 = { 42 43 00 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 }
        $code_160_3 = { A4 81 00 00 50 64 FF 35 00 00 00 00 8D 44 24 0C }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_160_3 at (pe.entry_point + 160))))
}

rule Trojan_WinPE_Gold
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_Gold"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "Length of Base64 encoded input string is not a multiple of 4." ascii wide
        $family_2 = "Illegal character in Base64 encoded data." ascii wide
        $family_3 = "^(1|3)[1-9A-HJ-NP-Za-km-z]{26,34}$" ascii wide
        $family_4 = "MS Sans Serif0" ascii wide
        $family_5 = "RESET TIMER!" ascii wide
        $family_6 = "[ ALTDOWN ]" ascii wide
        $family_7 = "[Passwords]" ascii wide
        $family_8 = "]nwoDegaP[" ascii wide
        $family_9 = "Fetch FF()" ascii wide
        $family_10 = "Full Time:" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule Trojan_WinPE_Inoci
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_Inoci"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "Decryption and save completed successfully!" ascii wide
        $family_2 = "AddNumbers function executed successfully!" ascii wide
        $family_3 = "Downloaded file is empty!" ascii wide
        $family_4 = "WinHttpCrackUrl() failed." ascii wide
        $family_5 = "WinHttpOpen() failed." ascii wide
        $family_6 = "CustomDownloader/1.0" ascii wide
        $family_7 = "Job Support.docx" ascii wide
        $family_8 = "ng c? hai file DLL!" ascii wide
        $family_9 = "Decrypted URL:" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule Trojan_WinPE_Kovter
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_Kovter"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)" ascii wide
        $family_2 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)" ascii wide
        $family_3 = "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko" ascii wide
        $family_4 = "=new%20ActiveXObject(\"WScript.Shell\");" ascii wide
        $family_5 = "try{moveTo(-100,-100);resizeTo(0,0);" ascii wide
        $family_6 = "try {jwplayer().play()} catch(e){}" ascii wide
        $family_7 = "+=String.fromCharCode(parseInt(" ascii wide
        $family_8 = "~\\VarFileInfo\\Translation" ascii wide
        $family_9 = "3.0.30729; InfoPath.3)" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule Trojan_WinPE_NetSupportManager
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_NetSupportManager"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "The file \"%s\" header is corrupt%The archive comment header is corrupt" ascii wide
        $family_2 = "Packed data CRC failed in %s" ascii wide
        $family_3 = "Storage_Enabled=0" ascii wide
        $family_4 = "Debug_Level=0" ascii wide
        $family_5 = "ZH\\tq2dhd" ascii wide
        $family_6 = "GK4{&wAW" ascii wide
        $ep_1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 7F 2D 00 00 }
        $code_080_1 = { 47 A6 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 }
        $code_112_1 = { 56 56 56 8D 45 E4 50 FF 15 4C 32 41 00 8D 45 E4 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_080_1 at (pe.entry_point + 80) and $code_112_1 at (pe.entry_point + 112))))
}

rule Trojan_WinPE_Protux
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_Protux"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "Save my answer as a permanent rule, and do not ask me next time." ascii wide
        $family_2 = "&Allow all hidden processes launched by" ascii wide
        $family_3 = "Microsft Corporation" ascii wide
        $family_4 = "Allow (recommended)" ascii wide
        $family_5 = "cmPQ]STaR" ascii wide
        $code_144_1 = { 2B 00 00 E8 66 FE FF FF 89 75 D0 8D 45 A4 50 FF }
        $code_224_1 = { 98 50 51 E8 B3 29 00 00 59 59 C3 8B 65 E8 FF 75 }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_144_1 at (pe.entry_point + 144) and $code_224_1 at (pe.entry_point + 224))))
}

rule Trojan_WinPE_Rhadamanthys
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_Rhadamanthys"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "! H.W d`&,.C.RW_u_P E A5 UU A o_dTX_CERF J_D l.W.hJA.7wE.6 oV.H>N_i< C_Z_wqZz" ascii wide
        $family_2 = "! s.w.Q!.c S.T.m e_r t.e_w.L5@20~^_c.0f r_a.K L&_M Fg j].L.Af.h.W~.H.Y.TZ_O_V-(_l}.2G.cC_t0 b.O" ascii wide
        $family_3 = "! w.t_n.0_k}.V_M{.U.d v y6.t_J.a.u.yv_x;H.S.VHh_u I1 mU1`.2 N(R.k.D.J M_Mn_B p.4.t" ascii wide
        $family_4 = "!C Q.Q.5_M Z.3.PopI.g$ m_p YFfP b3.x~b.MWu.UI.k.J h.W_Y t_TL S.Uk.D_j_a G_d_T1 B8 q.0" ascii wide
        $family_5 = "!N_b.o.C fc.b.M.S.PE aT.d_P0_g4o H.N2_V}_h Z DX_W U.uZH_Y.X.q_g4_Fk_S7a." ascii wide
        $family_6 = "!Y.BdyN_m_e.R^ v.p_I_K;W k_Ih6<r z.L c_I.6 q.c_b3.7H.0 G m V,.oz%p.f_Z.q_A" ascii wide
        $family_7 = "#.y_x.5 Mr.CK K O.n.B.Q.97.81l.v.y}.G.AG.kA_F_DwA s[ I_C Q[d T.v.H Cu_g_R.y O.w_Og?$_b.NJ_N" ascii wide
        $family_8 = "#.z.3 lw% U.V z33.W Q_W.6 l.d.V t?.q g c c vJ_v_O.B.j rt.G.0_CZ.G_sM|p" ascii wide
        $family_9 = "$ O.4.z.R_OL.i s yNoEE_I[h.z I X.n.rW_b_q L i_b.UQ y} i_v9.o! w[6 a L.F x." ascii wide
        $family_10 = "$ x I_J%C L X_DRF L_W.L.I r& Y u.D.p.p.K x.Po_e.8_k\\_p_b# a_B_l.gt_n.W.cX J T,e_n" ascii wide
        $family_11 = "$ xY2_V t+.r# WK[.0.3 c rvt nG*SI.W8_F ns^ N_bs c@ b_p[_u q D.Rw_B_I S_" ascii wide
        $family_12 = "$.D l B_MM.m Q Q_Cdf_o.oQ_I b_CS.L.t G3].w pP_k A h y{dX.l y.Y4#&_" ascii wide
        $family_13 = "$u_UGDt_EC_Uj.i.M NQ T.L.j_n hlY.z N L6.1QZm_j.J zL.Z uCs.e_X_N?" ascii wide
        $family_14 = "% Aj_Yt A.W u.r G_H_A.I.2XK_E_Dl.uQ k_r_u.W_kAE_S Qej ek.y S_iI-_r.U.8" ascii wide
        $family_15 = "%.2m.P.m.X.z]_xE.f.4.d].6.Z.vB_e:_I.i_g0 d.E> r_Bl.p_r2 Q.d_q_f.g J:1J^q_b%K.u.Q" ascii wide
        $family_16 = "%.i.n.VZ Z_j.K_g j_W_h_t wg N se|.0.UqK/7_hA p_I.5_M.j] H_wC!_Q.y.m.A a.u.r_C.r" ascii wide
        $code_048_1 = { 48 3B C8 74 14 33 C0 F0 48 0F B1 0D 28 41 07 00 }
        $code_080_1 = { 40 53 48 83 EC 20 0F B6 05 13 41 07 00 85 C9 BB }
        $code_112_1 = { 00 00 E8 85 13 00 00 84 C0 75 04 32 C0 EB 14 E8 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80) and $code_112_1 at (pe.entry_point + 112))))
}

rule Trojan_WinPE_Router
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_Router"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = "echo_and_return: socket() - Error at socket(): %ld" ascii wide
        $family_2 = "echo_and_return: send() is OK - Bytes sent: %ld" ascii wide
        $family_3 = "C:\\ping_pong\\win_client\\Release\\win_client.pdb" ascii wide
        $family_4 = "cmd.exe /C ping -w 50 -n 1 1.1.1.1 > Nul & Del" ascii wide
        $family_5 = "%s: option does not take an argument -- %.*s" ascii wide
        $family_6 = "echo_and_return: The test string sent: \"%s\"" ascii wide
        $family_7 = "%s: option requires an argument -- %.*s" ascii wide
        $family_8 = "echo_and_return: Sending echo token..." ascii wide
        $family_9 = "echo_and_return: send() error %ld." ascii wide
        $family_10 = "echo_and_return: connect() is OK." ascii wide
        $family_11 = "echo_and_return: socket() is OK." ascii wide
        $family_12 = "Client: Error at WSAStartup()." ascii wide
        $family_13 = "Client: WSAStartup() is OK." ascii wide
        $family_14 = "ADAMANDPRASHANTAREAWESOME" ascii wide
        $family_15 = "Attempting to execute: %s" ascii wide
        $ep_1 = { E8 78 04 00 00 E9 B3 FD FF FF 8B FF 55 8B EC 81 }
        $code_192_1 = { 85 DC FC FF FF FF 15 30 20 40 00 A3 90 30 40 00 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("ws2_32.dll", "WSAStartup") and pe.imports("ws2_32.dll", "connect") and $ep_1 at (pe.entry_point + 0) and $code_192_1 at (pe.entry_point + 192))))
}

rule Trojan_WinPE_ServStart
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_ServStart"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" ascii wide
        $family_2 = "Referer: http://%s:80/http://%s" ascii wide
        $family_3 = "10.0.14393.0 (rs1_release.160715-1616)" ascii wide
        $family_4 = "Clien Local RunProcess" ascii wide
        $ep_1 = { 55 8B EC 6A FF 68 70 61 40 00 68 50 39 40 00 64 }
        $code_064_1 = { 00 FF FF 15 7C 60 40 00 8B 0D B8 84 40 00 89 08 }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Trojan_WinPE_Spawnt
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_Spawnt"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = "Kl9GbGluY0hfKl9GbGluY0hfKg==" ascii wide
        $family_2 = "TlQ0IGhvc3Rpbmcgc2VydmljZQ==" ascii wide
        $family_3 = "WndVbm1hcFZpZXdPZlNlY3Rpb24=" ascii wide
        $family_4 = "UmVhZFByb2Nlc3NNZW1vcnk=" ascii wide
        $family_5 = "LkVYRQ==" ascii wide
        $ep_1 = { 68 3C 01 00 00 68 00 00 00 00 68 A8 7A 40 00 E8 }
        $code_064_1 = { 1C 3E 00 00 E8 EA 3B 00 00 E8 62 32 00 00 E8 FD }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Trojan_WinPE_Tinba
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_Tinba"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 8B FF 55 8B EC E8 66 56 00 00 E8 11 00 00 00 5D }
        $code_032_1 = { 8B FF 55 8B EC 6A FE 68 30 12 43 00 68 40 93 40 }
        $code_064_1 = { 30 43 00 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule Trojan_WinPE_Toga
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_Toga"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "\\Source\\third_party\\protobuf\\src\\google/protobuf/repeated_field.h" ascii wide
        $family_2 = "CheckClient filter, current client ret false,Filter[%s],hostName[%s]." ascii wide
        $family_3 = "d:\\stnts\\madhook\\sources\\driver\\objfre_wnet_amd64\\amd64\\EyMc64.pdb" ascii wide
        $family_4 = "d:\\stnts\\madhook\\sources\\driver\\objfre_wnet_x86\\i386\\EyMc32.pdb" ascii wide
        $ep_1 = { E8 36 C4 00 00 E9 95 FE FF FF CC CC CC CC CC CC }
        $code_128_1 = { 44 24 08 5F C3 8B 44 24 04 C3 CC CC CC CC CC CC }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_1 at (pe.entry_point + 0) and $code_128_1 at (pe.entry_point + 128))))
}

rule Trojan_WinPE_VBCode
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_VBCode"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = "Content-Disposition: multipart/form-data; name=\"uploadfile\"; filename=\"" ascii wide
        $family_2 = "^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$" ascii wide
        $family_3 = "3fbd04f5-b1ed-4060-99b9-fca7ff59c113" ascii wide
        $family_4 = "Temporary Directory * for" ascii wide
        $family_5 = "No rows were selectedf" ascii wide
        $family_6 = "?Mon Jul 28 00:35:10" ascii wide
        $family_7 = "CryptGetHashParam(2)" ascii wide
        $family_8 = "CryptSetHashParam(5)" ascii wide
        $family_9 = "\\chrome_decrypt.zip" ascii wide
        $family_10 = "_localtime unixel" ascii wide
        $family_11 = "@TITLE Removing" ascii wide
        $family_12 = "bl_!rootpagin$>" ascii wide
        $family_13 = "n-3_5_9\\R~ab\\VB" ascii wide
        $family_14 = "SQLite format #" ascii wide
        $family_15 = "y}+0X2q6.20s)?k" ascii wide
        $family_16 = "@StrFtpServer" ascii wide
        $ep_1 = { 68 84 CF 43 00 E8 EE FF FF FF 00 00 00 00 00 00 }
        $ep_2 = { 68 B4 C5 43 00 E8 EE FF FF FF 00 00 00 00 00 00 }
        $ep_3 = { 68 F8 3A 40 00 E8 EE FF FF FF 00 00 00 00 00 00 }
        $ep_4 = { 68 18 6D 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 }
        $ep_5 = { 68 38 D0 43 00 E8 F0 FF FF FF 00 00 00 00 00 00 }
        $ep_6 = { 68 20 49 40 00 E8 EE FF FF FF 00 00 00 00 00 00 }
        $code_032_1 = { B4 D4 63 4B 8A 5C 61 66 FD E6 A6 D5 00 00 00 00 }
        $code_032_3 = { 56 4E 0E 41 AD D6 55 1D B0 C6 88 C3 00 00 00 00 }
        $code_032_4 = { 36 F1 9E 47 A5 54 8C FD 40 1A 61 84 00 00 00 00 }
        $code_064_1 = { 65 63 74 31 00 C1 40 00 08 C1 40 00 00 00 00 00 }
        $code_064_2 = { 65 63 74 31 00 11 16 03 00 06 08 0F 00 00 00 00 }
        $code_064_3 = { 65 63 74 31 00 00 00 00 88 04 72 07 00 00 00 00 }
        $code_064_4 = { 69 72 65 77 61 6C 6C 00 00 00 00 00 41 64 76 61 }
        $code_080_4 = { 06 00 00 00 C4 17 40 00 56 42 35 21 36 26 2A 00 }
        $code_096_2 = { 0D 14 BC 4F C6 22 57 87 C4 4C 49 D7 44 9E 05 6F }
        $code_128_2 = { 00 00 00 00 B0 15 40 00 68 11 40 00 00 F0 30 00 }
        $code_192_1 = { 72 6D 31 00 0A 01 19 01 00 42 00 23 FF FF FF FF }
        $code_240_1 = { 46 03 FF 01 5A FF 00 00 01 08 00 50 69 63 74 75 }
        $code_240_2 = { 46 03 FF 01 8E 87 02 00 01 08 00 50 69 63 74 75 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_192_1 at (pe.entry_point + 192) and $code_240_1 at (pe.entry_point + 240))
                or ($code_064_1 at (pe.entry_point + 64) and $code_192_1 at (pe.entry_point + 192) and $code_240_2 at (pe.entry_point + 240))
                or ($ep_4 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64) and $code_096_2 at (pe.entry_point + 96))
                or ($ep_3 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_3 at (pe.entry_point + 64))
                or ($ep_5 at (pe.entry_point + 0) and $code_192_1 at (pe.entry_point + 192) and $code_240_2 at (pe.entry_point + 240))
                or ($ep_6 at (pe.entry_point + 0) and $code_032_3 at (pe.entry_point + 32) and $code_064_4 at (pe.entry_point + 64))
                or ($code_032_4 at (pe.entry_point + 32) and $code_080_4 at (pe.entry_point + 80) and $code_128_2 at (pe.entry_point + 128))
                or ($ep_2 at (pe.entry_point + 0) and $code_192_1 at (pe.entry_point + 192) and $code_240_2 at (pe.entry_point + 240))
                or ($code_064_1 at (pe.entry_point + 64) and $code_192_1 at (pe.entry_point + 192) and $code_240_1 at (pe.entry_point + 240))))
}

rule Trojan_WinPE_Vundo
{
    meta:
        description = "Static family string cluster for Trojan_WinPE_Vundo"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "SOFTWARE\\smartftp\\client 2.0\\settings\\general\\favorites" ascii wide
        $family_2 = "AppEvents\\Schemes\\Apps\\Explorer\\Navigating\\.current" ascii wide
        $family_3 = "SOFTWARE\\Classes\\MIME\\Database\\Content Type\\" ascii wide
        $family_4 = "SOFTWARE\\smartftp\\client 2.0\\settings\\backup" ascii wide
        $family_5 = "SOFTWARE\\martin prikryl\\winscp 2\\sessions" ascii wide
        $family_6 = "SOFTWARE\\Ghisler\\Total Commander" ascii wide
        $family_7 = "C:\\WINDOWS\\system32\\gbdwpbm.dll" ascii wide
        $family_8 = "SOFTWARE\\Far2\\Plugins\\ftp\\hosts" ascii wide
        $family_9 = "SOFTWARE\\Far\\Plugins\\ftp\\hosts" ascii wide
        $family_10 = "begun.ru/click.jsp?url=" ascii wide
        $family_11 = "http://mkkuei4kdsz.com/" ascii wide
        $family_12 = "http://ow5dirasuek.com/" ascii wide
        $family_13 = "Accept-Language: ru-RU" ascii wide
        $family_14 = "&ref=%s&real_refer=%s" ascii wide
        $family_15 = "SOFTWARE\\FlashFXP\\3" ascii wide
        $family_16 = "an.yandex.ru/count" ascii wide
        $ep_1 = { 55 8B EC B8 00 18 00 00 E8 5D 22 00 00 53 56 57 }
        $code_064_1 = { E8 FF FF 50 E8 91 F8 FF FF 85 C0 59 75 4C 56 8D }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule VirTool_WinPE_Upatre
{
    meta:
        description = "Static family string cluster for VirTool_WinPE_Upatre"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "play e:\\\\rrrtwr\\agef.wav alias PRFT" ascii wide
        $family_2 = "C:\\1454b7806f1f90644a3203aa26dc7502a2c2b87058a215e4417cac958a5504d8" ascii wide
        $family_3 = "C:\\219607c331aaf00eede9aa6e344c6a4a92970c94d32726a4bcd9fc41c37ec98d" ascii wide
        $family_4 = "C:\\4e7d606a88db6720beac9c1f26908e4e04fd210bcf8224469d69988d78c79a68" ascii wide
        $family_5 = "C:\\58e67d7e642a323ce87da7cc0470828d9306629ed9dd033c49ada609a4e39317" ascii wide
        $family_6 = "C:\\a04b2eadfe65b35484335c9f6a68598f38258045deb6031821a29cbbf294dab0" ascii wide
        $family_7 = "C:\\afec32cfa9b713a294ca97ecfdfd999a231487d801a54c910852f223f18df0e9" ascii wide
        $family_8 = "C:\\1RQEMay4.exe" ascii wide
        $family_9 = "C:\\3gw1AsXa.exe" ascii wide
        $family_10 = "C:\\4FAZ0BGZ.exe" ascii wide
        $family_11 = "C:\\5JhxdAh7.exe" ascii wide
        $family_12 = "C:\\5zsJe1fe.exe" ascii wide
        $family_13 = "C:\\6LyLWT89.exe" ascii wide
        $family_14 = "C:\\73gyVuIu.exe" ascii wide
        $family_15 = "C:\\9GasWflN.exe" ascii wide
        $family_16 = "C:\\Ai9uM1cC.exe" ascii wide
        $ep_1 = { E8 33 0B 00 00 A3 9E 30 40 00 6A 00 6A 00 FF 35 }
        $code_032_1 = { C3 63 0D 0A 04 AB A5 F1 C0 40 0A D1 B7 08 0A 04 }
        $code_064_1 = { FC 68 E1 0D 0A 04 73 7A B8 69 42 C9 38 45 01 0A }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule Virus_WinPE_Android
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Android"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "Set cdaudio door closed wait" ascii wide
        $family_2 = "Set cdaudio door open wait" ascii wide
        $family_3 = "2:2B2J2R2Z2b2j2r2{2" ascii wide
        $family_4 = "6#6,686=6F6O6X6a6j6" ascii wide
        $family_5 = "EInvalidPointer8e@" ascii wide
        $ep_1 = { 55 8B EC 83 C4 F4 B8 58 E9 40 00 E8 C0 6F FF FF }
        $code_064_1 = { E4 F9 FF FF 33 C0 5A 59 59 64 89 10 68 19 EA 40 }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Virus_WinPE_Begseabug
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Begseabug"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "sc config WinDefend start= disabled" ascii wide
        $family_2 = "sc config MpsSvc start= disabled" ascii wide
        $family_3 = "net stop WinDefend" ascii wide
        $family_4 = "net stop MpsSvc" ascii wide
        $family_5 = "2!(k-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" ascii wide
        $family_6 = "7,3 7k5!'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEESE]E" ascii wide
        $family_7 = "=EE+1*6.7+)k = EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" ascii wide
        $family_8 = "e(*! kHHOaEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" ascii wide
        $family_9 = "E-E EeE!E7E,E3E E7EeE#E*E7EeE1E-E EeE6E0E5E E7E&E*E*E)EeE!E7E,E3E E7EhE'E$E6E E!EeE1E*E*E)EEEEEqEOEDE" ascii wide
        $family_10 = "yCx]xZxaxhxqxEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" ascii wide
        $family_11 = "E0E5E E7E&E*E*E)EeE!E7E,E3E E7EhE'E$E6E E!EeE1E*E*E)EEEiEAEDE" ascii wide
        $family_12 = "E E7E6E,E*E+EEEEEtEkEuEkEuEkE|EpEuEEEsENEDE" ascii wide
        $family_13 = "=hEEEEEEEEEEEjEEEnEEEEEEEEEEEEEEEEEEEEEE" ascii wide
        $family_14 = "EEEEEEEEEEEEEEEEEEEEEEEEEEEk1 =1EEEJcEE" ascii wide
        $family_15 = "EjEjE2E2E2EkE<E*E0E7E6E,E1E EkE+E E1EEE" ascii wide
        $ep_1 = { 55 8B EC 81 EC CC 04 00 00 C7 85 14 FD FF FF 00 }
        $code_064_1 = { 85 1E FD FF FF 61 C6 85 1F FD FF FF 64 C6 85 20 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Virus_WinPE_Chir
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Chir"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "Net Send * My god! Some one killed ChineseHacker-2 Monitor" ascii wide
        $family_2 = "Content-Type: audio/x-wav; name=\"pp.exe\"" ascii wide
        $family_3 = "MAIL FROM: imissyou@btamail.net.cn" ascii wide
        $family_4 = "SUBJECT: %s is comming!" ascii wide
        $family_5 = "=.exetS=.scrtL=.htmt" ascii wide
        $family_6 = "=.wabt!=.adct%=r.dbt" ascii wide
        $family_7 = "Content-id: THE-CID" ascii wide
        $family_8 = "HELO btamail.net.cn" ascii wide
        $family_9 = "FROM: %s@yahoo.com" ascii wide
        $family_10 = "=winntv=windto" ascii wide
        $family_11 = "\\runouce.exe" ascii wide
        $family_12 = "RCPT TO: %s" ascii wide
        $ep_1 = { 60 E8 E6 19 00 00 8B 74 24 20 E8 08 00 00 00 61 }
        $code_032_1 = { F0 FF FF 81 EE 00 10 00 00 66 81 3E 4D 5A 75 F3 }
        $code_064_1 = { 33 C0 8B D6 83 C3 04 40 8B 3B 03 FA E8 0F 00 00 }
        $code_080_1 = { 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_080_1 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Virus_WinPE_Emdup
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Emdup"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_016_1 = { 03 00 00 A3 48 3F 43 00 89 0D 44 3F 43 00 89 15 }
        $code_080_1 = { 43 00 66 8C 25 28 3F 43 00 66 8C 2D 24 3F 43 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80))))
}

rule Virus_WinPE_Floxif
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Floxif"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "TTTTdcibTTTTz~QN" ascii wide
        $family_2 = "QMDVUCPG~OKAPM" ascii wide
        $family_3 = "QLeiIIII{lcn" ascii wide
        $family_4 = "_MZ[CBQX" ascii wide
        $code_064_1 = { F8 0F 82 68 03 00 00 0F BA 25 50 90 67 00 01 73 }
        $code_128_1 = { 50 90 67 00 00 0F 83 A7 01 00 00 F7 C7 03 00 00 }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_064_1 at (pe.entry_point + 64) and $code_128_1 at (pe.entry_point + 128))))
}

rule Virus_WinPE_HDrop
{
    meta:
        description = "Static family string cluster for Virus_WinPE_HDrop"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "VMProtect begin" ascii wide
        $family_2 = "VMProtect end" ascii wide
        $family_3 = "Tab/Enter" ascii wide
        $family_4 = "C:\\Program Files\\Common Files\\scvhost.exe" ascii wide
        $family_5 = "A Free Enterprise Instant Messenger" ascii wide
        $family_6 = "Rundll32 \"%s\",DllUpdate %s" ascii wide
        $ep_2 = { 55 8B EC 6A FF 68 08 E5 4D 00 68 44 3B 46 00 64 }
        $code_032_1 = { 53 56 57 89 65 E8 FF 15 80 01 48 00 33 D2 8A D4 }
        $code_064_2 = { B0 A8 51 00 C1 E1 08 03 CA 89 0D AC A8 51 00 C1 }
        $code_096_1 = { C0 75 08 6A 1C E8 C3 00 00 00 59 E8 3E 4E 00 00 }
    condition:
        (General_WinPE_AnySizePE and 3 of ($family_*))
        or (General_WinPE_AnySizePE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_1 at (pe.entry_point + 32) and $code_096_1 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))))
}

rule Virus_WinPE_Injexplorer
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Injexplorer"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "jmWjcj.jtjfWjsWjrjcjijmj.jejtjajdjpjujsjwWjdjnjijw" ascii wide
        $family_2 = "Windows Defender Extension" ascii wide
        $family_3 = "jmWjcj.jejljgWWjgj.jwjwjw" ascii wide
        $family_4 = "UjcjrjujojsUjRjfjoUjzjijS" ascii wide
        $family_5 = "OS: %s (language:0x%X)" ascii wide
        $ep_1 = { 55 8B EC 6A FF 68 F8 20 40 00 68 30 18 40 00 64 }
        $code_048_1 = { 15 D4 20 40 00 59 83 0D 90 30 40 00 FF 83 0D 94 }
        $code_080_1 = { 89 08 FF 15 CC 20 40 00 8B 0D 88 30 40 00 89 08 }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80))))
}

rule Virus_WinPE_Ipamor
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Ipamor"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "\\welcome.exe" ascii wide
        $family_2 = "c:\\mswdm.pro" ascii wide
        $family_3 = "\\mswdm.exe" ascii wide
        $family_4 = "Content-Type: text/x-msmsgsinvite; charset=UTF-8" ascii wide
        $family_5 = "Software\\Netscape\\Netscape Navigator\\Users\\%s" ascii wide
        $family_6 = "text/x-msmsgssystemmessage; charset=UTF-8" ascii wide
        $family_7 = "{05C9D843-C82C-4ac3-BCDA-2E74E78721AD}" ascii wide
        $family_8 = "{1DF57D09-637A-4ca5-91B9-2C3EDAAF62FE}" ascii wide
        $ep_2 = { 55 8B EC 6A FF 68 20 B2 40 00 68 AC 6F 40 00 64 }
        $code_064_1 = { EC E4 40 00 C1 E1 08 03 CA 89 0D E8 E4 40 00 C1 }
    condition:
        ((General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))) and
        ($family_2 and $family_3)
}

rule Virus_WinPE_Lamer
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Lamer"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "shell\\1\\Command=AutoRun.exe" ascii wide
        $family_2 = "shell\\2\\Command=AutoRun.exe" ascii wide
        $family_3 = "Outlook Express\\msimn.exe" ascii wide
        $family_4 = "Explorer.exe  HelpMe.exe" ascii wide
        $family_5 = "shellexecute=AutoRun.exe" ascii wide
        $family_6 = "Your disk is removed!" ascii wide
        $family_7 = "OnMouseWheelDown|FC" ascii wide
        $family_8 = "EInvalidPointer8y@" ascii wide
        $family_9 = "ParentBiDiMode\\lD" ascii wide
        $family_10 = "Stone,I hate you!" ascii wide
        $family_11 = "TCustomControl\\SC" ascii wide
        $family_12 = "open=AutoRun.exe" ascii wide
        $family_13 = "shell\\2\\=Browser" ascii wide
        $family_14 = "OnMouseWheel|FC" ascii wide
        $family_15 = "shell\\1\\Command" ascii wide
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
}

rule Virus_WinPE_Madang
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Madang"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "Angry Angel v3.0" ascii wide
        $family_2 = "\\Serverx.exe" ascii wide
        $family_3 = "\\updatex.exe" ascii wide
        $family_4 = "\\setupx.exe" ascii wide
        $family_5 = "http://vguarder.91i.net/SETUPX.EXE" ascii wide
        $family_6 = "C:\\setupx.dll" ascii wide
        $family_7 = "USR_Shohdi_Photo_USR`x" ascii wide
        $family_8 = "NDDEAPI - Server Side" ascii wide
        $ep_1 = { 60 78 03 79 01 EB E8 AF 14 00 00 8B 74 24 20 E8 }
        $code_032_1 = { 78 03 79 01 EB 59 E8 12 10 00 00 81 E6 00 F0 FF }
        $code_064_1 = { 5A 78 03 79 01 EB 75 EE 0F B7 7E 3C 03 FE 8B 6F }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule Virus_WinPE_Nemim
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Nemim"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = ",}ad,iprark!" ascii wide
        $family_2 = "B'UTT(eT" ascii wide
        $family_3 = "QRSTUVWXYZ[\\]^_@ABCDEFGHIJqrstuvwxyz{|}~" ascii wide
        $family_4 = "M`ylMbuqt/yLrxrPPPPPPPPPPPPPPPPP" ascii wide
        $family_5 = "q`[SSRRSdGZqtCSWWBuVGBRWuaaVFVFF" ascii wide
        $family_6 = "CLRLCRGB[KP=utyqP!ulvubP2!PFLRY" ascii wide
        $family_7 = "plgemauazi|es\\serveuame\\q}m" ascii wide
        $family_8 = "uree|lapelsfgd\\BBBsbaqe\\q}m" ascii wide
        $family_9 = "5c/q!-5c6q\"-5c6q#-5c6q$-5c" ascii wide
        $family_10 = "bcvy}ebLt||PPPPPPPPPPPPPPP" ascii wide
        $family_11 = "bcvy}ebLyldPPPPPPPPPPPPPPP" ascii wide
        $family_12 = "burlw}LtqvPPPPPPPPPPPPPPPP" ascii wide
        $family_13 = "c}qeulvLuzuPPPPPPPPPPPPPPP" ascii wide
        $family_14 = "gyl}cebLuzuPPPPPPPPPPPPPPP" ascii wide
        $family_15 = "qwvm}lebLuzuPPPPPPPPPPPPPP" ascii wide
        $family_16 = "t}qwrBLuzuPPPPPPPPPPPPPPPP" ascii wide
        $ep_1 = { 55 8B EC 81 EC 74 05 00 00 C7 85 D4 FE FF FF 00 }
        $code_064_1 = { 8B 85 D4 FE FF FF 83 E8 01 89 85 D4 FE FF FF 8B }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Virus_WinPE_Neshta
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Neshta"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "2#202B2J2R2_2k2x2" ascii wide
        $family_2 = "8&8,848F8R8a8m8u8" ascii wide
        $family_3 = "! Best regards 2 Tommy Salo. [Nov-2005] yours [Dziadulja Apanas]" ascii wide
        $family_4 = "Delphi-the best. Fuck off all the rest. Neshta 1.0 Made in Belarus." ascii wide
        $family_5 = "030F0X0\\0`0d0h0l0p0t0x0|0" ascii wide
        $code_064_1 = { B8 B4 91 40 00 B9 09 00 00 00 BA 09 00 00 00 E8 }
        $code_176_1 = { F4 FF FF E8 F4 FC FF FF B8 C4 91 40 00 B9 03 00 }
        $code_224_1 = { 45 E8 50 8D 45 E4 BA C4 91 40 00 B9 03 00 00 00 }
    condition:
        ((General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_064_1 at (pe.entry_point + 64) and $code_176_1 at (pe.entry_point + 176) and $code_224_1 at (pe.entry_point + 224))))) and
        ($family_3 and $family_4)
}

rule Virus_WinPE_PeClip
{
    meta:
        description = "Static family string cluster for Virus_WinPE_PeClip"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "RjdjljoYQjFj jljlRjhjSj\\_WPRPQjljpjxjEWjnQjijsPRjVjtjnRPPjujCWjsjwQjdjnjijWWjtjfQjsQPjcjijMWRPjajwjtjfQjSh" ascii wide
        $family_2 = "jnjcj.jmjdj5j6j2j.jwjwjwj/j/j:jpjt" ascii wide
        $family_3 = "jejdj SVjiRQWj<j;VWjbjnj&" ascii wide
        $family_4 = "shellexecute=page.pif" ascii wide
        $family_5 = "open=page.pif" ascii wide
        $ep_1 = { 55 8B EC 6A FF 68 50 45 40 00 68 4C 37 40 00 64 }
        $code_048_1 = { 42 40 00 59 83 0D 38 74 40 00 FF 83 0D 3C 74 40 }
        $code_080_1 = { FF 15 34 42 40 00 8B 0D 18 74 40 00 89 08 A1 38 }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80))))
}

rule Virus_WinPE_PurpleMood
{
    meta:
        description = "Static family string cluster for Virus_WinPE_PurpleMood"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "Content-Type: multipart/mixed;boundary=WC_MAIL_PaRt_BoUnDaRy_05151998" ascii wide
        $family_2 = "Content-Disposition: attachment; filename=PurpleMood.scr" ascii wide
        $family_3 = "--WC_MAIL_PaRt_BoUnDaRy_05151998--" ascii wide
        $family_4 = "RCPT TO: <test@pact518.hit.edu.cn>" ascii wide
        $family_5 = "--WC_MAIL_PaRt_BoUnDaRy_05151998" ascii wide
        $family_6 = "\\PurpleMood.scr" ascii wide
        $family_7 = "C:\\Windows\\system32\\PurpleMood.scr" ascii wide
        $ep_1 = { E8 00 00 00 00 5B 81 EB 05 40 40 00 E8 B0 00 00 }
        $code_064_1 = { 05 10 00 00 00 89 83 E2 55 40 00 8D 83 51 57 40 }
        $code_112_1 = { 00 E8 EB 14 00 00 FF B3 45 56 40 00 C3 8D 83 66 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64) and $code_112_1 at (pe.entry_point + 112))))
}

rule Virus_WinPE_Quervar
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Quervar"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "AkYrKHBGH\\bTRSGASer\\skbfYsYBr.res" ascii wide
        $family_2 = "BbiQTYESG\\yFsFfaynQ\\drEzBnSRS.xml" ascii wide
        $family_3 = "bfezzstsD\\NzbNdasDa\\iTbFKHTnQ.xml" ascii wide
        $family_4 = "brRFDbhFH\\bFhFnbeSQ\\rShrNsfhT.xml" ascii wide
        $family_5 = "BtGebZaNZ\\kDHfDBfta\\EYyiESkna.res" ascii wide
        $family_6 = "DaGRefShb\\bDQbHAZid\\KFNQAKHEA.res" ascii wide
        $family_7 = "dbBnRRzAa\\fRKHBtFSZ\\zKGthyGHt.xml" ascii wide
        $family_8 = "dDbTkkQsb\\ztTZEHddS\\GZtABQTDZ.xml" ascii wide
        $family_9 = "dHBHFzTbk\\zDkKAeaDD\\ffBBQBaaG.xml" ascii wide
        $family_10 = "dHbRHGGSR\\rdbGBsAed\\BSakSFhdh.xml" ascii wide
        $family_11 = "DhQTBSsiG\\AiFEdYNes\\RfDYiZybG.xml" ascii wide
        $family_12 = "dktSDFNDQ\\ySEkHQNBD\\dnffkDkhY.res" ascii wide
        $family_13 = "dYsaHKise\\FrAaFdQBK\\QtBAebBkQ.xml" ascii wide
        $family_14 = "EEADStRyK\\HKRKakRTT\\eFNBnHKhK.res" ascii wide
        $family_15 = "eKQDEETBR\\HKGndseQk\\ZYEdiriKY.res" ascii wide
        $family_16 = "enHfBrsEQ\\kbrBrSZSi\\GsYtGErkT.xml" ascii wide
        $ep_1 = { 55 8B EC B8 64 D2 00 00 E8 03 E8 00 00 56 57 C7 }
        $code_032_1 = { 4D F4 8B 55 F4 89 55 FC 6A 00 68 D0 01 00 00 6A }
        $code_064_1 = { 0F 84 6C 47 00 00 C7 85 C8 FE FF FF 00 00 00 00 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule Virus_WinPE_Ribaj
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Ribaj"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "gold is 1 part mercury and 3 parts sulfur" ascii wide
        $family_2 = "msil.jabir by alcopaul" ascii wide
        $family_3 = "X lyd ly" ascii wide
    condition:
        General_WinPE_ValidPE and 2 of ($family_*)
}

rule Virus_WinPE_Rungbu
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Rungbu"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "h&&&&&&&[5SROo" ascii wide
        $family_2 = "Csrqpnlj?i=" ascii wide
        $family_3 = "KK.xu7,GGr" ascii wide
        $family_4 = "Barang mewah kena pajak, nabung di bank tiap bulan potong pajak," ascii wide
        $family_5 = "Cuma udara yang dihirup yang tidak kena pajak, namun sudah tercemar" ascii wide
        $family_6 = "Malahan sekarang lebih lebih untuk masalah pilkada pilkada dan pilkada." ascii wide
        $family_7 = "Pantas bangsa Indonesia tidak bisa maju karena bangsanya bodoh." ascii wide
        $family_8 = "Pemerintah harus segera menghapuskan penggunaan MSG dipasaran!" ascii wide
        $family_9 = "Atau mereka terpilih karena terpintar diantara yang terbodoh," ascii wide
        $family_10 = "Sebenarnya siapa yang bisa ngomongin dengan pemerintah ?????" ascii wide
        $family_11 = "Indonesia penuh dengan pajak! Tidak heran penuh pembajak." ascii wide
        $family_12 = "Pemerintah sekarang ini lebih memilih uang uang dan uang." ascii wide
        $family_13 = "Flu burung, masa sich burungnya bisa flu? Tanya kenapa?" ascii wide
        $family_14 = "Tapi mudah-mudahan pemerintah sadar sendiri aja yaaa!!!" ascii wide
        $family_15 = "Hampir semua produk makanan Indonesia menggunakan MSG." ascii wide
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
}

rule Virus_WinPE_Spreadoc
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Spreadoc"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "X_BEP]]T_fX_U^FB" ascii wide
        $family_2 = "D_BEP]]TCfD_U^" ascii wide
        $family_3 = "d7{4MKvR(vq" ascii wide
        $family_4 = "RLGPBm&m?$)" ascii wide
        $family_5 = "eqL80h[OH{" ascii wide
        $family_6 = "gWMb!K\\?!9" ascii wide
        $family_7 = "NBIULys]]7" ascii wide
        $family_8 = ",xb\\nAq&{" ascii wide
        $family_9 = "4X'0@xkWW" ascii wide
        $family_10 = "[6VDS4IU@" ascii wide
        $family_11 = "d3=ErAYjf" ascii wide
        $family_12 = "dnFF-S%&H" ascii wide
        $family_13 = "hkW:Rx![U" ascii wide
        $family_14 = "nKUgkfu(-" ascii wide
        $family_15 = "tN9\\$ uHU" ascii wide
        $ep_1 = { E8 C5 55 00 00 E9 78 FE FF FF CC CC CC CC CC CC }
        $code_064_1 = { 0C 60 4D 00 00 74 16 57 56 83 E7 0F 83 E6 0F 3B }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Virus_WinPE_Synares
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Synares"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 83 C4 F0 B8 78 A7 49 00 E8 98 C1 F6 FF }
        $code_064_1 = { E8 CF FA FB FF A1 CC DB 49 00 8B 00 E8 43 FB FB }
    condition:
        (General_WinPE_AnySizePE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Virus_WinPE_Triusor
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Triusor"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "?%?+?1?7?J?T?Z?f?x?" ascii wide
        $family_2 = "3%3H3M3W3k3p3w3}3" ascii wide
        $family_3 = "8!8-8C8I8Z8l8r8" ascii wide
        $family_4 = "2=3B3O3a3m3r3" ascii wide
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
}

rule Virus_WinPE_Tufik
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Tufik"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "Provides support for driver software. This service can't be stopedcca" ascii wide
        $family_2 = "MS Driver Servcice Centeriep." ascii wide
        $family_3 = "Driver Centerxmf" ascii wide
        $ep_1 = { E8 00 00 00 00 5B 81 EB F2 08 40 00 FF 34 24 E8 }
        $ep_2 = { 68 00 04 00 00 68 8C 54 40 00 6A 00 E8 CD 1F 00 }
        $code_032_1 = { 05 40 00 8D 83 E4 05 40 00 50 FF B3 93 05 40 00 }
        $code_032_2 = { 68 8C 58 40 00 E8 56 20 00 00 8B F8 8B C8 83 EF }
        $code_064_1 = { 9B 05 40 00 8D 83 5A 06 40 00 50 FF B3 93 05 40 }
        $code_064_2 = { 8C 58 40 00 00 EB 02 E2 E5 68 8C 54 40 00 E8 2D }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or ($ep_2 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_064_2 at (pe.entry_point + 64))))
}

rule Virus_WinPE_Viking
{
    meta:
        description = "Static family string cluster for Virus_WinPE_Viking"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "A*\\AF:\\RFD\\xNewCode\\xNewPro\\xT\\trjFN\\Project1.vbp" ascii wide
        $family_2 = "C:\\Windows\\System32\\ieframe.dll" ascii wide
        $family_3 = "lIEObject_DocumentComplete" ascii wide
        $family_4 = "T^biYjZ\\nod M)z" ascii wide
        $family_5 = "pf_voe=NE.M6" ascii wide
        $family_6 = "bTIjE]1'7" ascii wide
        $family_7 = "CZ@4S1OiD" ascii wide
        $family_8 = "mSvIE[ON]" ascii wide
        $family_9 = "wJHU!(dTW" ascii wide
        $family_10 = "pxVjJ\\dO" ascii wide
        $ep_1 = { 68 DC 3A 40 00 E8 EE FF FF FF 00 00 48 00 00 00 }
        $code_032_1 = { 86 1A F4 47 A8 FB 94 FD 7A FD 93 F4 00 00 00 00 }
        $code_096_1 = { 02 00 00 00 01 00 00 00 7F A1 6C ED CC B4 F9 4B }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_096_1 at (pe.entry_point + 96))))
}

rule Worm_MSIL_Agent
{
    meta:
        description = "Static family string cluster for Worm_MSIL_Agent"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
        confidence = "high"
    strings:
        $family_1 = "ezB9OnsxfTp7Mn06ezN9Ons0fQ==" ascii wide
        $family_2 = "UHJvY2VzcyBTdGFydGVkIGF0OiA=" ascii wide
        $family_3 = "JWNvbW1hbmRTZW5kRmlsZSU=" ascii wide
        $family_4 = "R2V0QWN0aXZlV2luZG93cw==" ascii wide
        $family_5 = "SGlkZVVwZGF0ZVNjcmVlbg==" ascii wide
        $family_6 = "U2hvd1VwZGF0ZVNjcmVlbg==" ascii wide
        $family_7 = "V1NjcmlwdC5TaGVsbA==" ascii wide
        $family_8 = "aW1hZ2UvanBlZw==" ascii wide
        $family_9 = "JWNvbW1hbmQ2NCU=" ascii wide
        $family_10 = "JWNvbW1hbmQ2NSU=" ascii wide
        $family_11 = "JWNvbW1hbmQ3MiU=" ascii wide
        $family_12 = "JWNvbW1hbmQ3MSU=" ascii wide
        $family_13 = "R0VUV0NhbVBsdQ==" ascii wide
        $family_14 = "R0VUV21pY1BsdQ==" ascii wide
        $family_15 = "SW5zdGFsbG5nQw==" ascii wide
        $family_16 = "TmV0RGlzQ1ZFbmQ=" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule Worm_MSIL_Autorun
{
    meta:
        description = "Static family string cluster for Worm_MSIL_Autorun"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
    strings:
        $family_1 = "Botkiller" ascii wide
        $family_2 = "Domain: {1}{0}Cookie Name: {2}{0}Value: {3}{0}Path: {4}{0}Expired: {5}{0}HttpOnly: {6}{0}Secure: {7}" ascii wide
        $family_3 = "Mozilla/5.0 (Windows NT 6.3; rv:48.0) Gecko/20100101 Firefox/48.0" ascii wide
        $family_4 = "TypeSerializers have to implement IDynamicTypeSerializer or  IStaticTypeSerializer" ascii wide
        $family_5 = "Firefox does not have any profiles, has it ever been launched?" ascii wide
        $family_6 = "\"!#!(',+BADCHGIGRQUTVTWTZY[Y\\Y]Y^Y_Y`YaYedfdgdhdidjdlknmom" ascii wide
        $family_7 = "2No longer supported. Use AverageFrameRate instead." ascii wide
        $family_8 = "The video source does not support camera control." ascii wide
        $family_9 = "This video device does not report capabilities." ascii wide
        $family_10 = "Yandex\\YandexBrowser\\User Data\\Default\\Cookies" ascii wide
        $family_11 = "SOFTWARE\\Wow6432Node\\Mozilla\\Mozilla Firefox" ascii wide
        $family_12 = "No installs of firefox recorded in its key." ascii wide
        $family_13 = "/C vssadmin.exe Delete Shadows /All /Quiet" ascii wide
        $family_14 = "Failed creating device object for moniker." ascii wide
        $family_15 = "Firefox does not have any logins.json file" ascii wide
        $family_16 = "xClient.Core.NetSerializer.TypeSerializers" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule Worm_WinPE_Bladabindi
{
    meta:
        description = "Static family string cluster for Worm_WinPE_Bladabindi"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "https://dl.dropbox.com/s/p84aaz28t0hepul/Pass.exe?dl=0" ascii wide
        $family_2 = "cmd.exe /k ping 0 & del \"" ascii wide
        $family_3 = "taskkill /F /IM PING.EXE" ascii wide
        $family_4 = "/pass.exe" ascii wide
        $family_5 = "/temp.txt" ascii wide
        $code_112_2 = { 00 00 E4 04 00 00 00 00 00 00 3C 3F 78 6D 6C 20 }
        $code_128_3 = { 00 00 E4 04 00 00 00 00 00 00 3C 3F 78 6D 6C 20 }
        $code_144_1 = { 00 00 E4 04 00 00 00 00 00 00 3C 3F 78 6D 6C 20 }
        $code_160_3 = { 00 00 E4 04 00 00 00 00 00 00 3C 3F 78 6D 6C 20 }
        $code_176_3 = { 00 00 E4 04 00 00 00 00 00 00 3C 3F 78 6D 6C 20 }
        $code_176_5 = { 3E 0D 0A 3C 61 73 73 65 6D 62 6C 79 20 78 6D 6C }
        $code_192_5 = { 3E 0D 0A 3C 61 73 73 65 6D 62 6C 79 20 78 6D 6C }
        $code_208_1 = { 3E 0D 0A 3C 61 73 73 65 6D 62 6C 79 20 78 6D 6C }
        $code_224_3 = { 3E 0D 0A 3C 61 73 73 65 6D 62 6C 79 20 78 6D 6C }
        $code_240_3 = { 3E 0D 0A 3C 61 73 73 65 6D 62 6C 79 20 78 6D 6C }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.data_directories[14].size > 0 and $code_144_1 at (pe.entry_point + 144) and $code_208_1 at (pe.entry_point + 208))
                or (pe.data_directories[14].size > 0 and $code_160_3 at (pe.entry_point + 160) and $code_224_3 at (pe.entry_point + 224))
                or (pe.data_directories[14].size > 0 and $code_176_3 at (pe.entry_point + 176) and $code_240_3 at (pe.entry_point + 240))
                or (pe.data_directories[14].size > 0 and $code_128_3 at (pe.entry_point + 128) and $code_192_5 at (pe.entry_point + 192))
                or (pe.data_directories[14].size > 0 and $code_112_2 at (pe.entry_point + 112) and $code_176_5 at (pe.entry_point + 176))))
}

rule Worm_WinPE_Bloored
{
    meta:
        description = "Static family string cluster for Worm_WinPE_Bloored"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "27.0.0.1 securityresponse.symantec.com 127.0.0.1 google.ca 127.0.0.1 www.google.ca" ascii wide
        $family_2 = "Accessibility Wizard.There was a problem saving the specified file." ascii wide
        $family_3 = "Click or use the arrow keys to select the smallest text you can read:" ascii wide
        $family_4 = "Cursor Settings7You can change the blink rate and width of the cursor." ascii wide
        $family_5 = "For more information about using Windows for users with disabilities:" ascii wide
        $family_6 = "It's easier to see and follow the mouse pointer if it leaves a trail." ascii wide
        $family_7 = "It's easy to accidentally press CAPS LOCK, NUM LOCK, or SCROLL LOCK." ascii wide
        $family_8 = "Mouse Button Settings.You can change how the mouse buttons function." ascii wide
        $family_9 = "Mouse Cursor7You can choose the size and color of your mouse cursor." ascii wide
        $family_10 = "Save ChangesxDo you want to keep the changes you have made so far?" ascii wide
        $family_11 = "SoundSentry6Windows can display visual warnings for system sounds." ascii wide
        $family_12 = "You may want to configure your mouse to work with the hand you prefer." ascii wide
        $family_13 = "Icon Size5You can choose the size of the icons on your desktop." ascii wide
        $family_14 = ".<Large window titles and menus, and reduce screen resolution." ascii wide
        $family_15 = "I am &deaf or have difficulty hearing sounds from the computer" ascii wide
        $family_16 = "BounceKeys2You can set Windows to ignore repeated keystrokes." ascii wide
        $ep_1 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 20 }
        $code_064_1 = { 55 8B 0D 54 A5 44 00 89 E5 5D FF E1 8D 74 26 00 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Worm_WinPE_Delf
{
    meta:
        description = "Static family string cluster for Worm_WinPE_Delf"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $family_1 = "CKY3 - Bam Margera World Industries Alien Workshop Full Downloader.exe" ascii wide
        $family_2 = "[DiVX] Harry Potter And The Sorcerors Stone Full Downloader.exe" ascii wide
        $family_3 = "Star Wars Episode 2 - Attack Of The Clones Full Downloader.exe" ascii wide
        $family_4 = "Jenna Jameson - Built For Speed Downloader.exe" ascii wide
        $family_5 = "Key generator for all windows XP versions.exe" ascii wide
        $family_6 = "[DiVX] Lord of The Rings Full Downloader.exe" ascii wide
        $family_7 = "Sony Play station boot disc - Downloader.exe" ascii wide
        $family_8 = "StarWars2 - CloneAttack - FullDownloader.exe" ascii wide
        $family_9 = "Macromedia key generator (all products).exe" ascii wide
        $family_10 = "Macromedia Flash 5.0 Full Downloader.exe" ascii wide
        $family_11 = "Internet and Computer Speed Booster.exe" ascii wide
        $family_12 = "KaZaA media desktop v2.0 UNOFFICIAL.exe" ascii wide
        $family_13 = "Battle.net key generator (WORKS!!).exe" ascii wide
        $family_14 = "ZoneAlarm Firewall Full Downloader.exe" ascii wide
        $family_15 = "Cat Attacks Child Full Downloader.exe" ascii wide
        $family_16 = "AikaQuest3Hentai FullDownloader.exe" ascii wide
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
}

rule Worm_WinPE_Fasong
{
    meta:
        description = "Static family string cluster for Worm_WinPE_Fasong"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "- Dock zone has no control%List does not allow duplicates ($0%x)" ascii wide
        $family_2 = "Multipart/Alternative; boundary=\"----=_NextPart_000_000A_01BF9F1A\"" ascii wide
        $family_3 = "Content-Type: text/tab-separated-values; charset=" ascii wide
        $family_4 = "shutdown(Service failed in custom message(%d): %s" ascii wide
        $family_5 = ",Version: 5.3.0  Build:1055   Date:5/26/99" ascii wide
        $family_6 = "Initializaton of windows sockets failed" ascii wide
        $family_7 = "%Error removing control from dock tree" ascii wide
        $ep_1 = { 55 8B EC 83 C4 F0 33 C0 89 45 F0 B8 10 69 45 00 }
        $code_064_1 = { E8 DF C9 FF FF 8B 55 F0 A1 1C 89 45 00 E8 2E D0 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Worm_WinPE_Klez
{
    meta:
        description = "Static family string cluster for Worm_WinPE_Klez"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "Z<s-d1`/d0j3d3q4k2ank-v.k/`.k.f5kn7.d+r4v>d3cpv)cpu/e" ascii wide
        $family_2 = "tem32\\dllcac" ascii wide
        $family_3 = "j/j(}}Sl+me" ascii wide
        $code_144_1 = { 1F 00 00 E8 1C 1D 00 00 89 75 D0 8D 45 A4 50 FF }
        $code_208_1 = { A0 50 E8 0A 1D 00 00 8B 45 EC 8B 08 8B 09 89 4D }
    condition:
        (General_WinPE_ValidPE and 2 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_144_1 at (pe.entry_point + 144) and $code_208_1 at (pe.entry_point + 208))))
}

rule Worm_WinPE_Mydoom
{
    meta:
        description = "Static family string cluster for Worm_WinPE_Mydoom"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "VGKNTA@CBBEC@DP/" ascii wide
        $family_2 = "DDGF6n@$5" ascii wide
        $family_3 = "_Mxq?QQ." ascii wide
        $family_4 = "gold-QIca festn" ascii wide
        $family_5 = "ll5root\\IEFrame" ascii wide
        $family_6 = "(dnsapiUiphlp" ascii wide
        $family_7 = "%m-E-OPEoUT," ascii wide
        $family_8 = "?hm $A+rm b" ascii wide
        $family_9 = "a,.%$oLLKeA" ascii wide
        $family_10 = "tting,[AYs" ascii wide
        $family_11 = "eY Nam8H" ascii wide
        $ep_1 = { 60 BE 00 90 50 00 8D BE 00 80 FF FF 57 83 CD FF }
        $code_208_1 = { FF FF 5E 89 F7 B9 01 01 00 00 8A 07 47 2C E8 3C }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_208_1 at (pe.entry_point + 208))))
}

rule Worm_WinPE_Phorpiex
{
    meta:
        description = "Static family string cluster for Worm_WinPE_Phorpiex"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "%s:Zone.Identifier" ascii wide
        $family_2 = "Check the sender of this email, I have sent it from your email account." ascii wide
        $family_3 = "My Trojan allowed me to access your files, accounts, and your camera." ascii wide
        $family_4 = "To ensure you read this email, you will receive it multiple times." ascii wide
        $family_5 = "You can purchase Bitcoin (BTC) from reputable exchanges here:" ascii wide
        $family_6 = "If you want to find out more about it, simply use Google." ascii wide
        $family_7 = "After that, I removed my malware to leave no traces." ascii wide
        $family_8 = "I RECORDED YOU (through your camera) MASTURBATING!" ascii wide
        $family_9 = "Alternatively, simply Google for other exchanges." ascii wide
        $family_10 = "Unfortunately, there is some bad news for you." ascii wide
        $family_11 = "or Exodus Wallet to manage your transactions." ascii wide
        $family_12 = "YOU PERVERT, I RECORDED YOU!" ascii wide
        $family_13 = "http://icanhazip.com/" ascii wide
        $family_14 = "I keep my promises!" ascii wide
        $family_15 = "8&828W8\\8b8l8q8w8" ascii wide
        $ep_1 = { E8 7C 03 00 00 E9 36 FD FF FF 8B FF 55 8B EC 8B }
        $code_240_1 = { 09 00 00 00 8B 45 DC E8 1E 02 00 00 C3 6A 08 E8 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("ws2_32.dll", "WSAStartup") and pe.imports("ws2_32.dll", "connect") and $ep_1 at (pe.entry_point + 0) and $code_240_1 at (pe.entry_point + 240))))
}

rule Worm_WinPE_Picsys
{
    meta:
        description = "Static family string cluster for Worm_WinPE_Picsys"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "GV_J]BN][" ascii wide
        $family_2 = "hot tomoli lathering up sexy body for boyfriend's tongue.mpg.pif" ascii wide
        $family_3 = "movie of mom who whip hot ass on daughter's big cock lover.mpg.pif" ascii wide
        $family_4 = "Want to see a massive horse cock in a tight little teen's pussy.mpg.pif" ascii wide
        $family_5 = "cool rooster raiding hen house for hot babes, link city.mpg.pif" ascii wide
        $family_6 = "little brown cup-cake with plump boobs and sweet beaver.mpg.pif" ascii wide
        $family_7 = "cutie who became addicted to dildo and fired her lover.mpg.pif" ascii wide
        $family_8 = "wife in kitchen preparing hot pussy for hubby's dinner.mpg.pif" ascii wide
        $family_9 = "amateur slut fingering herself threw her wet panties.mpg.pif" ascii wide
        $family_10 = "amateur spreading more fine ass than stud can handle.mpg.pif" ascii wide
        $family_11 = "bigger chunky girl with huge tits posing in the buff.mpg.pif" ascii wide
        $family_12 = "firm ass honie with thick lips made for sucking rods.mpg.pif" ascii wide
        $family_13 = "hotties sucking boobs and eating snatch in large bed.mpg.pif" ascii wide
        $family_14 = "illegal porno - 15 year old raped by two men on boat.mpg.pif" ascii wide
        $family_15 = "two studs fucking the hell out of a slut from behind.mpg.pif" ascii wide
        $family_16 = "babe celebrating new years naked and spreading cunt.mpg.pif" ascii wide
        $ep_1 = { 55 8B EC 83 C4 E4 33 C0 89 45 E8 89 45 EC B8 D8 }
        $ep_2 = { 60 BE 15 70 45 00 8D BE EB 9F FA FF 57 83 CD FF }
        $code_032_1 = { 64 FF 30 64 89 20 33 C0 A3 EC CC 44 00 68 DC CC }
        $code_064_1 = { E8 17 65 FF FF 8B 45 EC E8 07 66 FF FF 50 68 02 }
        $code_208_2 = { FF FF 5E 89 F7 B9 3E 03 00 00 8A 07 47 2C E8 3C }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_208_2 at (pe.entry_point + 208))))
}

rule Worm_WinPE_Rebhip
{
    meta:
        description = "Static family string cluster for Worm_WinPE_Rebhip"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "&2csup=!o" ascii wide
        $family_2 = "7E7V7LAC?" ascii wide
        $family_3 = "Jm\\mnmjmk" ascii wide
        $family_4 = "p{nF]P/wx" ascii wide
        $family_5 = "P}t[fj]D0" ascii wide
        $family_6 = "3svo /yq" ascii wide
        $family_7 = "7ye5 gnQ" ascii wide
        $family_8 = "RPeBZ7L!" ascii wide
        $family_9 = "L$_RasDefaultCredentials#0" ascii wide
        $family_10 = "SOFTWARE\\Vitalwerks\\DUC" ascii wide
        $family_11 = "wptukstqrgdvef`abc\\]_" ascii wide
        $family_12 = "(unnamed password)" ascii wide
        $family_13 = "0UnitInjectLibrary" ascii wide
        $family_14 = "UnitInjectLibrary" ascii wide
        $family_15 = "(unnamed value)" ascii wide
        $code_016_1 = { B8 04 BB 40 00 E8 0A 78 FF FF 33 C0 55 68 C4 C0 }
        $code_080_1 = { 30 7A FF FF EB 06 53 E8 E8 78 FF FF 68 E8 C0 40 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80))))
}

rule Worm_WinPE_Specx
{
    meta:
        description = "Static family string cluster for Worm_WinPE_Specx"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $family_1 = "\\drivers32\\Age of Wonders II - Shadow Magic Serial Generator.exe" ascii wide
        $family_2 = "\\drivers32\\Battlefield 1942 - The Road to Rome Serial Generator.exe" ascii wide
        $family_3 = "\\drivers32\\Commandos 3 - Destination Berlin Serial Generator.exe" ascii wide
        $family_4 = "\\drivers32\\Conflict - Desert Storm II - Back to Baghdad No-Cd Crack.exe" ascii wide
        $family_5 = "\\drivers32\\Dark Age of Camelot - Trials of Atlantis No-Cd Crack.exe" ascii wide
        $family_6 = "\\drivers32\\Dark Age of Camelot - Trials of Atlantis Serial Generator.exe" ascii wide
        $family_7 = "\\drivers32\\Flight Simulator - Century of Flight Serial Generator.exe" ascii wide
        $family_8 = "\\drivers32\\Harry Potter - Quidditch World Cup Serial Generator.exe" ascii wide
        $family_9 = "\\drivers32\\IL-2 Sturmovik - Forgotten Battles Serial Generator.exe" ascii wide
        $family_10 = "\\drivers32\\Lord of the Rings - The Two Towers Serial Generator.exe" ascii wide
        $family_11 = "\\drivers32\\Lord of the Rings - War of the Ring Serial Generator.exe" ascii wide
        $family_12 = "\\drivers32\\Max Payne 2 - The Fall of Max Payne Serial Generator.exe" ascii wide
        $family_13 = "\\drivers32\\Medal of Honor - Allied Assault Breakthrough No-Cd Crack.exe" ascii wide
        $family_14 = "\\drivers32\\Network Cable e ADSL Speed 1.0.6 Serial Generator.exe" ascii wide
        $family_15 = "\\drivers32\\Neverwinter Nights - Shadows of Undrentide No-Cd Crack.exe" ascii wide
        $family_16 = "\\drivers32\\Return to Castle Wolfenstein Enemy Territory No-Cd Crack.exe" ascii wide
        $ep_1 = { 55 8B EC B9 8C 02 00 00 6A 00 6A 00 49 75 F9 53 }
        $code_032_1 = { 00 BF 14 AA 42 00 33 C0 55 68 41 37 42 00 64 FF }
        $code_064_1 = { FF FF 8B D8 85 DB 74 17 E8 67 34 FF FF 3D B7 00 }
    condition:
        (General_WinPE_ValidPE and 3 of ($family_*))
        or (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule Worm_WinPE_VBCode
{
    meta:
        description = "Static family string cluster for Worm_WinPE_VBCode"
        author = "PYAS Security"
        date = "2026-09-08"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
        confidence = "high"
    strings:
        $family_1 = "Gaara The Kazekage By : Paraysutki VM Community" ascii wide
        $family_2 = "http:/www.narutogames.com" ascii wide
        $family_3 = "Kota Cantik - Paray City" ascii wide
        $family_4 = "06.01.2008 (A) Update" ascii wide
        $family_5 = "Kazekage Games Action" ascii wide
        $family_6 = "Kazekage of the Sand" ascii wide
        $family_7 = "Kazekage Was Here" ascii wide
        $family_8 = "lyvn}tAb" ascii wide
    condition:
        General_WinPE_ValidPE and 3 of ($family_*)
}

rule Adware_WinPE_Adposhel
{
    meta:
        description = "Shared family entry-point code clusters for Adware_WinPE_Adposhel"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { E8 86 03 00 00 E9 85 FE FF FF 55 8B EC 56 FF 75 }
        $ep_2 = { E8 60 04 00 00 E9 85 FE FF FF 55 8B EC 56 FF 75 }
        $ep_3 = { E8 27 03 00 00 E9 85 FE FF FF 55 8B EC 56 FF 75 }
        $code_064_1 = { 83 EC 0C 8D 4D F4 E8 2B F6 FF FF 68 40 C1 7D 1D }
        $code_064_2 = { 56 FF 75 08 8B F1 E8 F6 CB FF FF C7 06 48 94 03 }
        $code_096_2 = { 08 00 C7 41 04 2C A4 6D 1D C7 01 24 A4 6D 1D C3 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_096_2 at (pe.entry_point + 96))))
}

rule Adware_WinPE_Imali
{
    meta:
        description = "Shared family entry-point code clusters for Adware_WinPE_Imali"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { E8 48 75 00 00 E9 89 FE FF FF 8B FF 55 8B EC 83 }
        $code_064_1 = { 45 F4 50 FF 75 F0 FF 75 E4 FF 75 E0 FF 15 C8 D0 }
        $code_096_1 = { 41 00 85 C0 74 02 FF D0 6A 19 E8 39 6D 00 00 6A }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64) and $code_096_1 at (pe.entry_point + 96))))
}

rule Backdoor_Win64_Meterpreter
{
    meta:
        description = "Shared family entry-point code clusters for Backdoor_Win64_Meterpreter"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 89 E5 53 81 EC 04 01 00 00 E8 CD FF FF FF A1 }
        $ep_2 = { 55 89 E5 83 EC 18 A1 04 F0 01 B1 8B 04 85 A0 6D }
        $code_032_2 = { 01 B1 C1 E0 07 83 C0 78 05 80 F0 01 B1 89 C4 A1 }
        $code_032_3 = { 02 EB 05 E8 98 FE FF FF B8 01 00 00 00 48 83 C4 }
        $code_048_3 = { 48 3B C8 74 14 33 C0 F0 48 0F B1 0D 20 32 00 00 }
        $code_064_1 = { C7 45 B8 01 00 C7 85 7C FF FF FF 0C 00 00 00 C7 }
        $code_064_2 = { F3 62 FF FF 83 EC 04 B8 00 00 00 00 EB 4D C7 44 }
        $code_080_3 = { 48 83 EC 28 85 C9 75 07 C6 05 09 32 00 00 01 E8 }
        $code_096_4 = { 24 30 00 00 00 00 C7 44 24 38 18 00 00 00 48 C7 }
        $code_112_1 = { 04 00 00 00 00 8D 85 7C FF FF FF 89 04 24 A1 CC }
        $code_144_3 = { EC 20 80 3D D0 31 00 00 00 8B D9 75 67 83 F9 01 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64) and $code_112_1 at (pe.entry_point + 112))
                or ($ep_2 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_032_3 at (pe.entry_point + 32) and $code_096_4 at (pe.entry_point + 96))
                or ($code_048_3 at (pe.entry_point + 48) and $code_080_3 at (pe.entry_point + 80) and $code_144_3 at (pe.entry_point + 144))))
}

rule Backdoor_WinPE_Agent
{
    meta:
        description = "Shared family entry-point code clusters for Backdoor_WinPE_Agent"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 55 8B EC B9 30 00 00 00 6A 00 6A 00 49 75 F9 51 }
        $ep_2 = { 60 BE 00 80 47 00 8D BE 00 90 F8 FF C7 87 B8 07 }
        $ep_3 = { E9 BB 79 00 00 E9 06 B1 00 00 E9 3B 81 01 00 E9 }
        $ep_4 = { 55 8B EC 6A FF 68 70 61 40 00 68 40 39 40 00 64 }
        $code_016_4 = { F6 75 09 83 3D 14 6F 09 10 00 EB 26 83 FE 01 74 }
        $code_048_2 = { DB 72 ED 9C 31 C0 40 9D 01 DB 75 07 8B 1E 83 EE }
        $code_064_2 = { 00 FF FF 15 80 60 40 00 8B 0D A8 84 40 00 89 08 }
        $code_064_3 = { 00 E9 AA F8 00 00 E9 17 A0 00 00 E9 70 06 00 00 }
        $code_064_4 = { 85 C0 75 04 33 C0 EB 4E 57 56 53 E8 B3 7D FE FF }
        $code_080_1 = { 33 D2 55 68 09 FA 48 00 64 FF 32 64 89 22 8D 4D }
        $code_112_2 = { C9 EB 52 29 C9 83 E8 03 72 11 C1 E0 08 8A 06 46 }
        $code_128_4 = { 74 11 A1 0C 79 09 10 85 C0 74 08 57 56 53 FF D0 }
        $code_176_4 = { 25 94 72 08 10 FF 25 A4 72 08 10 FF 25 A0 72 08 }
        $code_240_4 = { 04 77 F1 01 CF E9 2C FF FF FF 5E 56 5F B9 1D 4D }
        $code_240_8 = { 04 77 F1 01 CF E9 2C FF FF FF 5E 89 F7 B9 1D 4D }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_1 at (pe.entry_point + 0) and $code_080_1 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_048_2 at (pe.entry_point + 48) and $code_112_2 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_064_4 at (pe.entry_point + 64) and $code_176_4 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_4 at (pe.entry_point + 16) and $code_128_4 at (pe.entry_point + 128))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_240_4 at (pe.entry_point + 240))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_112_2 at (pe.entry_point + 112) and $code_240_8 at (pe.entry_point + 240))))
}

rule Backdoor_WinPE_Berbew
{
    meta:
        description = "Berbew entrypoint evidence or XOR-key-independent payload strings with PE and API context"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "rule-local signature conjunction with PE structure/import constraints; corpus provenance not embedded"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
        confidence = "high"
        refinement = "requires three correlated positional features; generic PE headers, sparse data and standalone NOP blocks excluded"
        attribution_basis = "Berbew/Padodor payload markers; directory labels are not attribution evidence"
    strings:
        $v1_ep  = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 23 00 00 }
        $v1_32  = { 00 30 00 10 FF D0 5F 5E 5B C9 C2 0C 00 B8 01 00 }
        $v1_48  = { 00 00 EB F2 55 89 E5 83 EC 0C 57 6A 00 6A F6 E8 }

        $v2_ep  = { 01 1D 1D 19 53 46 46 1D 1B 1C 1A 1D 44 0B 08 07 }
        $v2_16  = { 02 47 1B 1C 46 0B 08 1A 0C 1A 46 19 69 19 05 06 }
        $v2_32  = { 0E 47 19 01 19 56 4C 1A 53 4C 69 53 4C 69 53 4C }

        $v3_ep  = { D2 1E 43 00 DF 1E 43 00 EC 1E 43 00 F9 1E 43 00 }
        $v3_16  = { 06 1F 43 00 13 1F 43 00 20 1F 43 00 2D 1F 43 00 }
        $v3_32  = { 3A 1F 43 00 47 1F 43 00 54 1F 43 00 61 1F 43 00 }

        $ext_cache = "FindFirstUrlCacheEntryA" ascii fullword
        $ext_desktop = "SetThreadDesktop" ascii fullword
        $ext_acl = "SetEntriesInAclA" ascii fullword
    condition:
        (General_WinPE_ValidPE and
        pe.machine == 0x014c and
        (
            ($v1_ep at pe.entry_point and $v1_32 at pe.entry_point + 32 and $v1_48 at pe.entry_point + 48) or
            ($v2_ep at pe.entry_point and $v2_16 at pe.entry_point + 16 and $v2_32 at pe.entry_point + 32) or
            ($v3_ep at pe.entry_point and $v3_16 at pe.entry_point + 16 and $v3_32 at pe.entry_point + 32)
        )) or
        (General_WinPE_AnySizePE and all of ($ext_*) and
        pe.number_of_sections >= 4 and pe.number_of_sections <= 12 and
        pe.imports("WININET.dll", "FindFirstUrlCacheEntryA") and
        pe.imports("USER32.dll", "SetThreadDesktop") and
        pe.imports("ADVAPI32.dll", "SetEntriesInAclA") and
        for any s in (0..pe.number_of_sections-1) : (
            pe.sections[s].name == ".data" and
            pe.sections[s].raw_data_size >= 4096 and pe.sections[s].raw_data_size <= 65536 and
            (pe.sections[s].characteristics & pe.SECTION_MEM_WRITE) != 0 and
            for any p in (pe.sections[s].raw_data_offset..pe.sections[s].raw_data_offset+pe.sections[s].raw_data_size-87) : (
                (uint32(p) ^ uint32(p + 4)) == 0x4e071312 and (uint32(p) ^ uint32(p + 8)) == 0x4f2e4523 and (uint32(p) ^ uint32(p + 12)) == 0x52070230 and
                (uint32(p + 59) ^ uint32(p + 59 + 4)) == 0x1e003b3f and (uint32(p + 59) ^ uint32(p + 59 + 8)) == 0x09060125 and (uint32(p + 59) ^ uint32(p + 59 + 12)) == 0x090f0a1c and (uint32(p + 59) ^ uint32(p + 59 + 16)) == 0x09211c30 and (uint32(p + 59) ^ uint32(p + 59 + 20)) == 0x201c093f and
                for any q in (pe.sections[s].raw_data_offset..p-16) : (
                    (uint32(q) ^ uint32(q + 4)) == 0x63241751 and (uint32(q) ^ uint32(q + 8)) == 0x36721a00
                )
            )
        ))
}

rule Backdoor_WinPE_Farfli
{
    meta:
        description = "Shared family entry-point code clusters for Backdoor_WinPE_Farfli"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_3 = { 55 8B EC 6A FF 68 98 44 40 00 68 EE 32 40 00 64 }
        $ep_4 = { 55 8B EC 6A FF 68 58 6D 40 00 68 72 31 40 00 64 }
        $ep_6 = { 55 8B EC 6A FF 68 38 21 40 00 68 50 1E 40 00 64 }
        $ep_7 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 60 70 00 00 }
        $code_016_1 = { F6 75 09 83 3D F4 E0 00 10 00 EB 26 83 FE 01 74 }
        $code_048_1 = { 30 40 00 59 83 0D E8 44 40 00 FF 83 0D EC 44 40 }
        $code_048_2 = { 20 40 00 59 83 0D 18 35 40 00 FF 83 0D 1C 35 40 }
        $code_064_4 = { 00 FF FF 15 E0 20 40 00 8B 0D 68 53 41 00 89 08 }
        $code_064_5 = { 00 FF FF 15 C0 14 43 00 8B 0D 8C 04 43 00 89 08 }
        $code_064_6 = { 00 FF FF 15 00 5E 41 00 8B 0D F4 3F 41 00 89 08 }
        $code_080_1 = { FF 15 B4 30 40 00 8B 0D DC 44 40 00 89 08 A1 B8 }
        $code_080_2 = { FF 15 B0 20 40 00 8B 0D 0C 35 40 00 89 08 A1 B4 }
        $code_096_6 = { 75 E4 FF 75 E0 FF 15 8C 22 02 10 C9 C2 08 00 8B }
        $code_112_8 = { 00 00 00 E8 D5 3A 00 00 59 59 85 DB 74 04 8B C3 }
        $code_128_1 = { 40 00 59 E8 E8 00 00 00 68 18 30 40 00 68 14 30 }
        $code_128_2 = { 74 11 A1 FC E0 00 10 85 C0 74 08 57 56 53 FF D0 }
        $code_128_3 = { 40 00 59 E8 EE 00 00 00 68 18 40 40 00 68 14 40 }
        $code_176_8 = { EB 07 E8 28 0F 00 00 89 30 E8 21 0F 00 00 89 30 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_128_2 at (pe.entry_point + 128))
                or ($code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80) and $code_128_3 at (pe.entry_point + 128))
                or ($code_048_2 at (pe.entry_point + 48) and $code_080_2 at (pe.entry_point + 80) and $code_128_1 at (pe.entry_point + 128))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_5 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_6 at (pe.entry_point + 0) and $code_064_4 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_064_6 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_7 at (pe.entry_point + 0) and $code_096_6 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_112_8 at (pe.entry_point + 112) and $code_176_8 at (pe.entry_point + 176))))
}

rule Backdoor_WinPE_Lotok
{
    meta:
        description = "Shared family entry-point code clusters for Backdoor_WinPE_Lotok"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_2 = { E8 43 D8 00 00 E9 78 FE FF FF 50 64 FF 35 00 00 }
        $ep_3 = { 55 8B EC 6A FF 68 F8 57 40 00 68 B6 3C 40 00 64 }
        $ep_4 = { 55 89 D3 E9 0C 00 04 00 00 C0 7A 63 B0 2C 7D 63 }
        $ep_5 = { 48 83 EC 28 48 8B 05 F5 62 07 00 C7 00 01 00 00 }
        $ep_7 = { E8 6F 03 00 00 E9 71 FE FF FF CC CC CC CC CC CC }
        $ep_8 = { 55 8B EC 6A FF 68 F0 36 40 00 68 8C 2C 40 00 64 }
        $ep_9 = { 55 8B EC 6A FF 68 78 65 40 00 68 40 33 40 00 64 }
        $ep_10 = { 55 8B EC 6A FF 68 58 85 41 00 68 8C 47 41 00 64 }
        $ep_11 = { 48 83 EC 28 E8 53 02 00 00 48 83 C4 28 E9 7A FE }
        $ep_13 = { E8 F9 0C 00 00 E9 7A FE FF FF 3B 0D 80 95 77 00 }
        $ep_14 = { E8 A3 05 00 00 E9 7A FE FF FF 55 8B EC 6A 00 FF }
        $ep_15 = { 55 8B EC 6A FF 68 B0 71 40 00 68 60 44 40 00 64 }
        $ep_17 = { 48 83 EC 28 E8 93 3C 00 00 48 83 C4 28 E9 76 FE }
        $code_032_6 = { C2 0C 00 8B FF 55 8B EC 8B 4D 08 53 33 DB 56 57 }
        $code_064_1 = { 64 C8 76 63 05 00 00 00 00 00 00 00 50 C0 7A 63 }
        $code_064_3 = { 00 FF FF 15 84 52 40 00 8B 0D 20 75 40 00 89 08 }
        $code_064_4 = { 48 83 EC 28 E8 6F 7C 00 00 48 83 F8 01 19 C0 48 }
        $code_064_6 = { 48 0F B1 0D 70 6D 01 00 75 EE 32 C0 48 83 C4 28 }
        $code_064_7 = { 00 FF FF 15 58 32 40 00 8B 0D BC 56 40 00 89 08 }
        $code_064_8 = { 00 FF FF 15 10 67 41 00 8B 0D B8 BE 41 00 89 08 }
        $code_080_2 = { 89 28 8B E8 A1 04 1C 49 00 33 C5 50 89 65 F0 FF }
        $code_096_3 = { DA 8B D1 8A 06 88 02 42 46 3A C3 74 03 4F 75 F3 }
        $code_128_1 = { 40 00 59 E8 FA 00 00 00 68 34 75 40 00 68 30 74 }
        $code_160_8 = { E8 9A 02 00 00 EB 18 E8 C1 08 00 00 50 E8 19 09 }
        $code_160_9 = { 8B 45 00 A3 D4 0E 44 00 8B 45 04 A3 D8 0E 44 00 }
        $code_160_10 = { 5B C9 C2 0C 00 CC CC CC CC CC 6A 00 6A 02 6A 00 }
        $code_176_11 = { 88 00 00 00 48 8D 0D 81 67 01 00 FF 15 B3 E7 00 }
        $code_192_10 = { 00 74 0A 6A 0C 56 E8 0F 06 00 00 59 59 8B C6 5E }
        $code_192_13 = { 56 56 FF 15 98 70 40 00 50 E8 68 F2 FF FF 89 45 }
        $code_224_11 = { 00 84 C0 75 07 E8 0B 09 00 00 EB ED B0 01 C3 E8 }
    condition:
        (General_WinPE_AnySizePE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_5 at (pe.entry_point + 0) and $code_064_4 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_080_2 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_6 at (pe.entry_point + 32) and $code_096_3 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_7 at (pe.entry_point + 0) and $code_192_10 at (pe.entry_point + 192))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_11 at (pe.entry_point + 0) and $code_064_6 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_8 at (pe.entry_point + 0) and $code_064_7 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_10 at (pe.entry_point + 0) and $code_064_8 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_9 at (pe.entry_point + 0) and $code_128_1 at (pe.entry_point + 128))
                or (pe.imports("ws2_32.dll", "WSAStartup") and pe.imports("ws2_32.dll", "connect") and $code_160_8 at (pe.entry_point + 160) and $code_224_11 at (pe.entry_point + 224))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_17 at (pe.entry_point + 0) and $code_176_11 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_13 at (pe.entry_point + 0) and $code_160_10 at (pe.entry_point + 160))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_15 at (pe.entry_point + 0) and $code_192_13 at (pe.entry_point + 192))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_14 at (pe.entry_point + 0) and $code_160_9 at (pe.entry_point + 160))))
}

rule Backdoor_WinPE_Meterpreter
{
    meta:
        description = "Shared family entry-point code clusters for Backdoor_WinPE_Meterpreter"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_3 = { 90 92 40 FC F5 41 4A D6 49 99 FD 42 99 9B 98 FC }
        $code_048_1 = { AC 3C 61 7C 02 2C 20 41 C1 C9 0D 41 01 C1 E2 ED }
        $code_064_3 = { 3F 42 37 90 9F F8 FC 93 98 9B E9 C6 0E 00 00 FF }
        $code_144_1 = { 4C 03 4C 24 08 45 39 D1 75 D8 58 44 8B 40 24 49 }
        $code_192_1 = { 41 5A 48 83 EC 20 41 52 FF E0 58 41 59 5A 48 8B }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_048_1 at (pe.entry_point + 48) and $code_144_1 at (pe.entry_point + 144) and $code_192_1 at (pe.entry_point + 192))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))))
}

rule Backdoor_WinPE_OnionDuke
{
    meta:
        description = "Shared family entry-point code clusters for Backdoor_WinPE_OnionDuke"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 27 3B 00 00 }
        $code_240_1 = { 59 6A 00 FF 15 D4 60 01 10 68 60 62 01 10 FF 15 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_240_1 at (pe.entry_point + 240))))
}

rule Backdoor_WinPE_Qbot
{
    meta:
        description = "Shared family entry-point code clusters for Backdoor_WinPE_Qbot"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 50 55 89 E5 83 C4 FC 52 C7 04 E4 00 00 FF FF E8 }
        $ep_2 = { 55 8B EC 66 3B C9 74 00 51 8B 45 0C 3A F6 74 03 }
        $ep_3 = { 83 7C 24 08 01 75 05 E8 12 2D 00 00 FF 74 24 04 }
        $code_032_2 = { EF 55 8B EC EB 02 5D C3 FF 75 14 FF 75 10 EB 00 }
        $code_064_1 = { 04 E4 40 29 1C E4 83 BB A8 4D 45 00 00 75 0E 50 }
        $code_064_2 = { 83 C4 10 EB E1 55 8B EC 66 3B ED 0F 84 C4 03 00 }
        $code_080_3 = { 04 83 FD 04 72 70 56 E8 56 2D 00 00 8B F0 3B F5 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or ($ep_2 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_080_3 at (pe.entry_point + 80))))
}

rule Backdoor_WinPE_Tofsee
{
    meta:
        description = "Shared family entry-point code clusters for Backdoor_WinPE_Tofsee"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_096_1 = { BD 64 FD FF FF 22 75 2A 8D 85 65 FD FF FF 50 8D }
        $code_208_1 = { 83 C4 28 39 5D FC 0F 84 C5 00 00 00 8B 45 FC 8D }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_096_1 at (pe.entry_point + 96) and $code_208_1 at (pe.entry_point + 208))))
}

rule HackTool_WinPE_GoToResolve
{
    meta:
        description = "Shared family entry-point code clusters for HackTool_WinPE_GoToResolve"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { E8 64 0E 00 00 E9 78 FE FF FF CC CC CC CC CC CC }
        $code_080_1 = { 8B 4D F4 64 89 0D 00 00 00 00 59 5F 5E 5B C9 C3 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_080_1 at (pe.entry_point + 80))))
}

rule Ransom_Win64_Lockfile
{
    meta:
        description = "Shared family entry-point code clusters for Ransom_Win64_Lockfile"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 48 83 EC 28 E8 57 0A 00 00 48 83 C4 28 E9 72 FE }
        $code_176_1 = { 48 85 C0 74 24 33 C9 E8 AC FA FF FF 84 C0 74 19 }
        $code_208_1 = { 30 33 C0 48 83 C4 20 5F C3 B9 07 00 00 00 E8 69 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_176_1 at (pe.entry_point + 176) and $code_208_1 at (pe.entry_point + 208))))
}

rule Ransom_WinPE_Crysis
{
    meta:
        description = "Shared family entry-point code clusters for Ransom_WinPE_Crysis"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 81 EC B0 01 00 00 C7 85 64 FE FF FF 00 }
        $code_064_1 = { C4 14 68 80 00 00 00 68 80 E0 40 00 68 DA 05 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Ransom_WinPE_Filecoder
{
    meta:
        description = "Shared family entry-point code clusters for Ransom_WinPE_Filecoder"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { E9 48 7B 00 00 E9 74 A9 03 00 E9 FB 87 01 00 E9 }
        $ep_2 = { 48 83 EC 28 48 8B 05 A5 E4 4B 00 C7 00 00 00 00 }
        $ep_3 = { E9 94 7D 00 00 E9 7A A3 03 00 E9 32 63 01 00 E9 }
        $code_064_1 = { 00 E9 BD A8 03 00 E9 EF 86 03 00 E9 FE A1 03 00 }
        $code_064_2 = { 00 E9 C3 A2 03 00 E9 B0 B2 03 00 E9 70 9F 03 00 }
        $code_096_2 = { 55 48 89 E5 48 81 EC 90 00 00 00 48 8B 05 D6 B7 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_096_2 at (pe.entry_point + 96))))
}

rule Ransom_WinPE_GenaLocker
{
    meta:
        description = "Shared family entry-point code clusters for Ransom_WinPE_GenaLocker"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { E8 DB 04 00 00 E9 7A FE FF FF 55 8B EC F6 45 08 }
        $code_032_1 = { F3 FA FF FF 59 59 8B C6 5E 5D C2 04 00 55 8B EC }
        $code_144_1 = { 8D 45 F4 50 E8 E3 05 00 00 CC E9 17 1C 00 00 55 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_144_1 at (pe.entry_point + 144))))
}

rule Ransom_WinPE_LockFile
{
    meta:
        description = "Shared family entry-point code clusters for Ransom_WinPE_LockFile"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { E8 F3 06 00 00 E9 74 FE FF FF 55 8B EC 6A 00 FF }
        $ep_2 = { 55 8B EC 6A FF 68 40 31 40 00 68 B0 22 40 00 64 }
        $ep_5 = { E8 33 0B 00 00 E9 74 FE FF FF CC CC CC CC CC CC }
        $ep_6 = { E8 F1 07 00 00 E9 7A FE FF FF 8B 4D F4 64 89 0D }
        $ep_7 = { 83 EC 1C C7 04 24 01 00 00 00 FF 15 A0 94 4E 00 }
        $code_032_2 = { 06 0F AD D0 D3 EA C3 8B C2 33 D2 80 E1 1F D3 E8 }
        $code_032_5 = { 83 EC 1C C7 04 24 02 00 00 00 FF 15 A0 94 4E 00 }
        $code_048_1 = { 30 40 00 59 83 0D 54 41 40 00 FF 83 0D 58 41 40 }
        $code_048_4 = { 71 02 10 74 0A 6A 0C 56 E8 78 F9 FF FF 59 59 8B }
        $code_048_5 = { 48 3B C8 74 14 33 C0 F0 48 0F B1 0D 7C 3F 00 00 }
        $code_064_1 = { 14 33 C0 F0 48 0F B1 0D 3C 84 03 00 75 EE 32 C0 }
        $code_064_2 = { 03 83 C7 02 8B 45 08 8B 70 0C 85 F6 74 24 FF 75 }
        $code_064_4 = { 06 0F A5 C2 D3 E0 C3 8B D0 33 C0 80 E1 1F D3 E2 }
        $code_064_5 = { B0 41 00 85 C0 74 05 6A 02 59 CD 29 A3 18 3C 42 }
        $code_064_6 = { 30 40 00 85 C0 74 05 6A 02 59 CD 29 A3 60 51 40 }
        $code_064_7 = { FF 25 F0 94 4E 00 8D B4 26 00 00 00 00 8D 76 00 }
        $code_064_8 = { 53 56 57 89 28 8B E8 A1 74 F0 49 00 33 C5 50 FF }
        $code_080_1 = { FF 15 B4 30 40 00 8B 0D 4C 41 40 00 89 08 A1 B0 }
        $code_080_4 = { 8C F5 FF FF C7 06 E8 71 02 10 8B C6 5E 5D C2 04 }
        $code_096_1 = { 85 C9 75 07 C6 05 25 84 03 00 01 E8 50 F7 FF FF }
        $code_096_3 = { 11 57 8B D6 E8 01 07 00 00 59 85 C0 78 04 33 C0 }
        $code_112_6 = { 02 10 C7 01 E8 71 02 10 C3 55 8B EC 83 EC 0C 8D }
        $code_128_3 = { 48 51 40 00 66 8C 05 44 51 40 00 66 8C 25 40 51 }
        $code_144_6 = { EC 20 80 3D 2C 3F 00 00 00 8B D9 75 67 83 F9 01 }
        $code_160_1 = { EC 83 03 00 00 8B D9 75 67 83 F9 01 77 6A E8 99 }
        $code_160_2 = { 8B 05 FA 18 2D 00 FF D0 48 89 C1 48 89 0C 24 48 }
        $code_160_3 = { 85 F6 74 07 83 C6 02 EB 02 33 F6 8B 17 85 D2 74 }
        $code_160_9 = { 9A FF FF 6A 07 6A 00 6A 00 FF 15 44 51 41 00 8D }
        $code_160_10 = { 8B 45 00 A3 9C 2C 42 00 8B 45 04 A3 A0 2C 42 00 }
        $code_160_11 = { 8B 45 00 A3 5C 5E 42 00 8B 45 04 A3 60 5E 42 00 }
        $code_176_13 = { 8D 0D A6 DC 02 00 E8 51 A1 00 00 85 C0 75 10 48 }
        $code_224_3 = { 00 48 8B 05 28 18 2D 00 FF D0 48 83 C4 30 C3 CC }
        $code_224_13 = { 00 00 83 C4 08 6B 45 FC 03 50 68 2C 42 41 00 E8 }
        $code_240_9 = { 7F 05 7E DC 02 00 48 89 05 87 DC 02 00 C6 05 51 }
    condition:
        (General_WinPE_AnySizePE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_064_1 at (pe.entry_point + 64) and $code_096_1 at (pe.entry_point + 96) and $code_160_1 at (pe.entry_point + 160))
                or ($code_064_2 at (pe.entry_point + 64) and $code_096_3 at (pe.entry_point + 96) and $code_160_3 at (pe.entry_point + 160))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_160_2 at (pe.entry_point + 160) and $code_224_3 at (pe.entry_point + 224))
                or ($ep_2 at (pe.entry_point + 0) and $code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80))
                or ($ep_5 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_064_4 at (pe.entry_point + 64))
                or ($code_048_4 at (pe.entry_point + 48) and $code_080_4 at (pe.entry_point + 80) and $code_112_6 at (pe.entry_point + 112))
                or (pe.imports("advapi32.dll", "CryptAcquireContextA") and pe.imports("advapi32.dll", "CryptEncrypt") and $code_064_6 at (pe.entry_point + 64) and $code_128_3 at (pe.entry_point + 128))
                or (pe.imports("advapi32.dll", "CryptAcquireContextA") and pe.imports("advapi32.dll", "CryptEncrypt") and $ep_1 at (pe.entry_point + 0) and $code_064_5 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_6 at (pe.entry_point + 0) and $code_064_8 at (pe.entry_point + 64))
                or (pe.imports("wininet.dll", "InternetOpenA") and pe.imports("wininet.dll", "InternetConnectA") and $code_048_5 at (pe.entry_point + 48) and $code_144_6 at (pe.entry_point + 144))
                or ($ep_7 at (pe.entry_point + 0) and $code_032_5 at (pe.entry_point + 32) and $code_064_7 at (pe.entry_point + 64))
                or (pe.imports("advapi32.dll", "CryptAcquireContextA") and pe.imports("advapi32.dll", "CryptEncrypt") and $ep_1 at (pe.entry_point + 0) and $code_160_10 at (pe.entry_point + 160))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_160_9 at (pe.entry_point + 160) and $code_224_13 at (pe.entry_point + 224))
                or (pe.imports("advapi32.dll", "CryptAcquireContextA") and pe.imports("advapi32.dll", "CryptEncrypt") and $ep_1 at (pe.entry_point + 0) and $code_160_11 at (pe.entry_point + 160))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_176_13 at (pe.entry_point + 176) and $code_240_9 at (pe.entry_point + 240))))
}

rule Ransom_WinPE_Lyposit
{
    meta:
        description = "Shared family entry-point code clusters for Ransom_WinPE_Lyposit"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 6A 58 68 50 7F 41 00 E8 22 15 00 00 33 F6 89 75 }
        $code_064_1 = { B9 0B 01 00 00 66 39 88 18 00 40 00 75 19 83 B8 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Ransom_WinPE_Necne
{
    meta:
        description = "Shared family entry-point code clusters for Ransom_WinPE_Necne"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { E8 32 FD FF FF 6A 00 FF 15 3C 10 40 00 CC 55 8B }
        $code_032_1 = { 50 57 89 45 FC 89 45 F8 E8 FA 86 FF FF 83 C4 0C }
        $code_064_1 = { E8 86 A0 FF FF 8B D8 85 DB 75 3E 57 FF 15 C0 10 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule Ransom_WinPE_Sodinokibi
{
    meta:
        description = "Shared family entry-point code clusters for Ransom_WinPE_Sodinokibi"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_2 = { 6A 00 E8 4D FF FF FF 6A 00 E8 75 0D 00 00 59 C3 }
        $ep_4 = { 55 8B EC FF 75 08 FF 15 1C D0 00 10 83 6D 0C 01 }
        $code_016_4 = { 55 8B EC 83 EC 2C 8D 45 D4 56 50 6A 18 5E 56 FF }
        $code_032_2 = { 00 8B D8 E8 25 15 00 00 B9 00 06 00 00 66 3B C1 }
        $code_032_3 = { 18 D0 00 10 A3 04 31 01 10 33 C0 40 5D C2 0C 00 }
        $code_048_4 = { 8B 45 E6 0F AF 45 E4 53 57 33 FF 47 0F B7 C0 66 }
        $code_064_1 = { 10 85 C0 0F 84 90 01 00 00 8B 45 E6 0F AF 45 E4 }
        $code_064_2 = { E2 02 00 00 8D 45 F8 C7 45 F8 04 01 00 00 50 8D }
        $code_064_4 = { 75 08 FF 15 64 21 01 10 85 C0 0F 84 90 01 00 00 }
        $code_080_3 = { 6A 08 5B 66 3B C3 76 16 6A 10 5B 66 3B C3 76 0E }
        $code_096_1 = { 26 6A 04 5B 66 3B C3 76 1E 6A 08 5B 66 3B C3 76 }
        $code_128_1 = { 6A 28 EB 11 6A 20 5B 8B C7 8A CB D3 E0 8D 04 85 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_064_1 at (pe.entry_point + 64) and $code_096_1 at (pe.entry_point + 96) and $code_128_1 at (pe.entry_point + 128))
                or ($ep_2 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_064_2 at (pe.entry_point + 64))
                or ($code_016_4 at (pe.entry_point + 16) and $code_048_4 at (pe.entry_point + 48) and $code_080_3 at (pe.entry_point + 80))
                or ($ep_4 at (pe.entry_point + 0) and $code_032_3 at (pe.entry_point + 32) and $code_064_4 at (pe.entry_point + 64))))
}

rule Rootkit_WinPE_Agent
{
    meta:
        description = "Shared family entry-point code clusters for Rootkit_WinPE_Agent"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 48 83 EC 28 48 83 3D 24 30 00 00 00 74 0A 48 83 }
        $ep_2 = { 48 83 EC 28 48 83 3D 3C 30 00 00 00 74 0A 48 83 }
        $ep_3 = { 40 53 48 83 EC 50 48 8B D9 48 8D 15 E0 03 00 00 }
        $code_032_1 = { 84 04 00 00 48 8D 15 55 07 00 00 33 C9 48 83 C4 }
        $code_032_2 = { EC 03 00 00 48 8D 4C 24 40 FF 15 D9 0F 00 00 48 }
        $code_032_3 = { 10 05 00 00 48 8D 15 E5 07 00 00 33 C9 48 83 C4 }
        $code_048_1 = { 48 83 EC 28 E8 33 00 00 00 48 83 C4 28 C3 CC CC }
        $code_064_1 = { 40 53 48 83 EC 20 48 8B DA 33 D2 48 8B CB FF 15 }
        $code_064_2 = { 8D 44 24 40 C6 44 24 28 00 33 D2 83 64 24 20 00 }
        $code_064_3 = { 68 48 8B 08 48 39 41 08 75 60 48 8B 50 08 48 39 }
        $code_080_1 = { 48 8D 15 E9 FF FF FF 48 3B C2 74 05 E8 EF 03 00 }
        $code_240_1 = { 39 00 75 0D 48 83 C1 08 48 8D 41 08 48 3B C7 76 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80) and $code_240_1 at (pe.entry_point + 240))
                or ($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))
                or ($ep_3 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_064_2 at (pe.entry_point + 64))
                or ($ep_2 at (pe.entry_point + 0) and $code_032_3 at (pe.entry_point + 32) and $code_064_3 at (pe.entry_point + 64))))
}

rule Rootkit_WinPE_DevCtrl
{
    meta:
        description = "Shared family entry-point code clusters for Rootkit_WinPE_DevCtrl"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 6A 60 68 40 90 41 00 E8 34 1B 00 00 BF 94 00 00 }
        $code_064_1 = { 8B 76 0C 81 E6 FF 7F 00 00 89 35 94 10 42 00 83 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Rootkit_WinPE_Trex
{
    meta:
        description = "Shared family entry-point code clusters for Rootkit_WinPE_Trex"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 8B FF 55 8B EC E8 BD FF FF FF 5D E9 1E D8 F6 FF }
        $code_080_1 = { 09 00 00 00 00 00 F6 81 09 00 16 82 09 00 2E 82 }
        $code_112_1 = { 09 00 88 82 09 00 98 82 09 00 A2 82 09 00 B8 82 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_080_1 at (pe.entry_point + 80) and $code_112_1 at (pe.entry_point + 112))))
}

rule TrojanDownloader_MSIL_Small
{
    meta:
        description = "Shared family entry-point code clusters for TrojanDownloader_MSIL_Small"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { FF 25 00 20 40 00 68 74 74 70 73 3A 2F 2F 63 64 }
        $code_016_1 = { 6E 00 64 00 50 00 52 00 4F 00 54 00 45 00 43 00 }
        $code_064_2 = { 38 37 38 30 32 31 33 36 37 37 34 32 37 33 34 33 }
        $code_064_3 = { 48 FF 25 C5 78 01 00 CC 48 8B C4 48 89 58 08 48 }
        $code_096_1 = { 5C 00 46 00 72 00 61 00 6D 00 50 00 52 00 4F 00 }
        $code_128_2 = { DA 4C 8D 43 04 E8 E6 06 00 00 8B 45 04 24 66 F6 }
        $code_160_2 = { 11 4C 8B CF 4D 8B C6 48 8B D6 48 8B CD E8 E6 2B }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.data_directories[14].size > 0 and $code_016_1 at (pe.entry_point + 16) and $code_096_1 at (pe.entry_point + 96))
                or (pe.data_directories[14].size > 0 and $ep_1 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or ($code_064_3 at (pe.entry_point + 64) and $code_128_2 at (pe.entry_point + 128) and $code_160_2 at (pe.entry_point + 160))))
}

rule TrojanDownloader_Win64_Agent
{
    meta:
        description = "Shared family entry-point code clusters for TrojanDownloader_Win64_Agent"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 48 83 EC 28 E8 6F F4 FF FF 48 83 C4 28 EB 09 CC }
        $ep_2 = { 48 83 EC 28 E8 27 06 00 00 48 83 C4 28 E9 7A FE }
        $ep_4 = { 48 83 EC 28 48 8B 05 B5 46 00 00 C7 00 01 00 00 }
        $code_032_1 = { 48 83 EC 28 48 8B 05 95 46 00 00 C7 00 00 00 00 }
        $code_048_1 = { 48 8D 4C 24 40 FF 15 D5 57 06 00 90 65 48 8B 04 }
        $code_080_1 = { B1 1D AA A5 05 00 0F 85 E2 97 02 00 8B 05 02 A6 }
        $code_128_2 = { 48 83 EC 48 48 8D 44 24 68 4C 89 4C 24 68 4D 89 }
        $code_160_2 = { CC CC 66 66 0F 1F 84 00 00 00 00 00 48 3B 0D E9 }
        $code_160_3 = { 55 57 56 53 48 83 EC 38 4C 89 C6 48 89 CB 48 89 }
        $code_192_2 = { C3 48 C1 C9 10 E9 26 07 00 00 CC CC 48 89 5C 24 }
        $code_240_3 = { 48 89 C1 48 8B 44 24 28 48 89 43 10 48 85 ED 75 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_160_3 at (pe.entry_point + 160) and $code_240_3 at (pe.entry_point + 240))
                or ($ep_2 at (pe.entry_point + 0) and $code_160_2 at (pe.entry_point + 160) and $code_192_2 at (pe.entry_point + 192))
                or ($ep_4 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_128_2 at (pe.entry_point + 128))))
}

rule TrojanDownloader_Win64_MalDownload
{
    meta:
        description = "Shared family entry-point code clusters for TrojanDownloader_Win64_MalDownload"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { E8 7E 03 00 00 E9 36 FD FF FF 8B FF 55 8B EC 8B }
        $code_080_1 = { 00 FF 15 34 40 40 00 33 C0 C3 CC FF 25 10 41 40 }
        $code_128_1 = { F8 FF 75 0C FF 75 08 FF 15 BC 40 40 00 59 EB 67 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_080_1 at (pe.entry_point + 80) and $code_128_1 at (pe.entry_point + 128))))
}

rule TrojanDownloader_WinPE_Agent
{
    meta:
        description = "Shared family entry-point code clusters for TrojanDownloader_WinPE_Agent"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_2 = { E8 7E 03 00 00 E9 37 FD FF FF 8B FF 55 8B EC 8B }
        $ep_6 = { 48 8B 05 E9 2F 00 00 C7 00 00 00 00 00 E9 9E FE }
        $ep_27 = { 68 24 63 41 00 E8 F0 FF FF FF 00 00 00 00 00 00 }
        $code_016_2 = { 6A 58 68 70 61 40 00 E8 14 08 00 00 33 DB 89 5D }
        $code_016_5 = { 25 00 00 00 00 81 EC 30 06 00 00 53 55 56 57 B9 }
        $code_016_7 = { 4D 8B C8 48 8B C1 4D 85 C0 74 1A 48 2B D1 66 90 }
        $code_032_1 = { 02 00 00 B8 00 00 03 00 49 89 C3 B8 00 00 01 00 }
        $code_032_4 = { 48 89 CA 48 8D 0D 86 5C 00 00 E9 D1 0D 00 00 90 }
        $code_080_3 = { 48 8B F9 49 8B C8 0F B6 C2 F3 AA 48 8B 3C 24 49 }
        $code_080_4 = { 00 FF 15 50 20 40 00 33 C0 C3 CC FF 25 BC 20 40 }
        $code_080_7 = { 48 83 EC 38 45 31 C9 31 C9 4C 8D 05 50 2C 00 00 }
        $code_096_1 = { 00 51 8D 4C 24 1C C7 84 24 50 06 00 00 00 00 00 }
        $code_128_1 = { 35 EC 7C 40 00 68 DC 10 40 00 68 D0 10 40 00 E8 }
        $code_128_3 = { F8 FF 75 0C FF 75 08 FF 15 64 20 40 00 59 EB 67 }
        $code_160_1 = { 48 8B 01 49 89 C3 48 8B 45 E8 8B 00 49 89 C2 4C }
        $code_160_2 = { 40 00 FF D6 89 45 E4 FF 35 80 33 40 00 FF D6 59 }
        $code_160_6 = { 00 A5 09 01 00 9E 08 01 00 00 08 00 66 72 6D 4C }
        $code_176_1 = { 00 39 35 EC 7C 40 00 75 1B 68 CC 10 40 00 68 C4 }
        $code_208_1 = { 55 48 89 E5 48 81 EC 30 00 00 00 48 89 4D 10 48 }
        $code_208_6 = { 3F 43 00 22 03 23 46 08 01 00 6C 74 00 00 3E 08 }
        $code_224_2 = { 83 C4 14 A3 80 33 40 00 C7 45 FC FE FF FF FF E8 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_032_1 at (pe.entry_point + 32) and $code_160_1 at (pe.entry_point + 160) and $code_208_1 at (pe.entry_point + 208))
                or ($code_016_2 at (pe.entry_point + 16) and $code_128_1 at (pe.entry_point + 128) and $code_176_1 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_5 at (pe.entry_point + 16) and $code_096_1 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_7 at (pe.entry_point + 16) and $code_080_3 at (pe.entry_point + 80))
                or ($ep_2 at (pe.entry_point + 0) and $code_080_4 at (pe.entry_point + 80) and $code_128_3 at (pe.entry_point + 128))
                or ($ep_6 at (pe.entry_point + 0) and $code_032_4 at (pe.entry_point + 32) and $code_080_7 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_160_2 at (pe.entry_point + 160) and $code_224_2 at (pe.entry_point + 224))
                or ($ep_27 at (pe.entry_point + 0) and $code_160_6 at (pe.entry_point + 160) and $code_208_6 at (pe.entry_point + 208))))
}

rule TrojanDownloader_WinPE_Amadey
{
    meta:
        description = "Shared family entry-point code clusters for TrojanDownloader_WinPE_Amadey"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_2 = { E8 8E 04 00 00 E9 74 FE FF FF 55 8B EC 83 EC 0C }
        $code_064_1 = { 01 00 85 C0 0F 84 A9 01 00 00 83 65 F0 00 33 C0 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_2 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule TrojanDownloader_WinPE_Delf
{
    meta:
        description = "Shared family entry-point code clusters for TrojanDownloader_WinPE_Delf"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 55 8B EC 83 C4 F0 B8 5C 86 47 00 E8 A4 E3 F8 FF }
        $ep_2 = { 55 8B EC 83 C4 F0 B8 F4 3A 45 00 E8 00 24 FB FF }
        $ep_4 = { 55 8B EC 83 C4 F0 B8 0C DE 46 00 E8 08 6C F9 FF }
        $ep_5 = { 55 8B EC 83 C4 F0 B8 60 6D 47 00 E8 94 ED F8 FF }
        $ep_6 = { 55 8B EC 83 C4 F0 B8 48 03 45 00 E8 0C 5B FB FF }
        $ep_7 = { 55 8B EC 83 C4 F0 B8 EC 2F 47 00 E8 7C 35 F9 FF }
        $ep_8 = { 55 8B EC 83 C4 F0 B8 B4 CA 45 00 E8 68 97 FA FF }
        $ep_9 = { 55 8B EC 83 C4 F0 B8 BC 27 46 00 E8 1C 3C FA FF }
        $ep_10 = { 55 8B EC 83 C4 F0 B8 A0 68 46 00 E8 70 F8 F9 FF }
        $ep_12 = { 55 8B EC 83 C4 F0 B8 44 FA 49 00 E8 14 61 F6 FF }
        $ep_13 = { 55 8B EC 83 C4 F0 B8 38 1C 48 00 E8 8C 4B F8 FF }
        $ep_15 = { 55 8B EC 83 C4 F0 B8 00 76 46 00 E8 E4 E8 F9 FF }
        $ep_16 = { 55 8B EC 83 C4 F0 B8 00 26 47 00 E8 20 43 F9 FF }
        $ep_17 = { 55 8B EC 83 C4 F0 B8 E0 0E 46 00 E8 CC 5A FA FF }
        $ep_19 = { 55 8B EC 83 C4 F0 B8 A0 B9 47 00 E8 B0 A1 F8 FF }
        $ep_21 = { 55 8B EC 83 C4 F0 B8 6C 64 46 00 E8 48 FD F9 FF }
        $code_064_1 = { 15 18 64 47 00 E8 02 48 FE FF A1 B4 A2 47 00 8B }
        $code_064_3 = { C4 0D 4B 00 8B 00 E8 ED 6C FE FF E8 A0 4B F9 FF }
        $code_064_4 = { 5B 00 8B 0D 40 68 45 00 A1 D4 69 45 00 8B 00 8B }
        $code_064_5 = { E8 83 CD FF FF A1 30 20 45 00 8B 00 E8 F7 CD FF }
        $code_064_6 = { 00 8B 00 E8 8C 32 FE FF E8 FB CB F8 FF 8D 40 00 }
        $code_064_7 = { FD FF A1 A8 65 47 00 8B 00 C6 40 5B 00 A1 A8 65 }
        $code_064_8 = { 00 8B 15 C8 C2 45 00 E8 50 A3 FF FF A1 78 D0 49 }
        $code_064_9 = { F8 ED 47 00 8B 00 E8 21 B9 FE FF E8 58 1F F9 FF }
        $code_064_10 = { E8 F7 36 FC FF E8 92 3D F6 FF 8B C0 00 00 00 00 }
        $code_064_14 = { E8 0F 50 FF FF A1 D4 81 46 00 8B 00 E8 83 50 FF }
        $code_064_15 = { 46 00 E8 9D 7C FE FF A1 DC AB 46 00 8B 00 C6 40 }
        $code_064_16 = { 00 8B 15 3C F6 47 00 E8 6C 0C FE FF A1 84 36 48 }
        $code_064_17 = { ED 47 00 8B 00 8B 15 24 B7 47 00 E8 64 4E FE FF }
        $code_064_21 = { 46 00 E8 55 62 FF FF A1 0C 32 46 00 8B 00 E8 C9 }
        $code_064_22 = { 00 8B 15 CC 31 46 00 E8 9C 5C FF FF 8B 0D 88 1E }
        $code_144_2 = { E0 25 40 00 BC 29 40 00 00 CB CC C8 C9 D7 CF C8 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_4 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_5 at (pe.entry_point + 0) and $code_064_6 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_6 at (pe.entry_point + 0) and $code_064_5 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_8 at (pe.entry_point + 0) and $code_064_8 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_7 at (pe.entry_point + 0) and $code_064_7 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_15 at (pe.entry_point + 0) and $code_064_15 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_16 at (pe.entry_point + 0) and $code_064_9 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_13 at (pe.entry_point + 0) and $code_064_16 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_10 at (pe.entry_point + 0) and $code_064_14 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_9 at (pe.entry_point + 0) and $code_144_2 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_12 at (pe.entry_point + 0) and $code_064_10 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_17 at (pe.entry_point + 0) and $code_064_21 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_19 at (pe.entry_point + 0) and $code_064_17 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_21 at (pe.entry_point + 0) and $code_064_22 at (pe.entry_point + 64))))
}

rule TrojanDownloader_WinPE_Lotok
{
    meta:
        description = "Shared family entry-point code clusters for TrojanDownloader_WinPE_Lotok"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 48 83 EC 20 48 8B EC 90 48 8D 0D 38 C4 FE FF }
        $ep_2 = { 55 48 83 EC 20 48 8B EC 90 48 8D 0D B8 E0 FE FF }
        $ep_3 = { 55 48 83 EC 20 48 8B EC 90 48 8D 0D 18 0E FF FF }
        $ep_4 = { E8 76 73 00 00 E9 89 FE FF FF 8B FF 55 8B EC 53 }
        $code_032_4 = { 00 75 18 E8 5D 6D 00 00 6A 1E E8 A7 6B 00 00 68 }
        $code_064_1 = { 8B 15 7A BD FE FF 4C 8B 05 EB 4D 09 00 E8 0E 39 }
        $code_064_2 = { 8B 15 F2 D9 FE FF 4C 8B 05 8B 1D 07 00 E8 7E D1 }
        $code_064_3 = { 8B 15 6A 07 FF FF 4C 8B 05 5B 34 06 00 E8 8E 02 }
        $code_064_4 = { C3 EB 03 33 C0 40 50 6A 00 FF 35 B0 4B 42 00 FF }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))
                or ($ep_4 at (pe.entry_point + 0) and $code_032_4 at (pe.entry_point + 32) and $code_064_4 at (pe.entry_point + 64))))
}

rule TrojanDownloader_WinPE_Maloader
{
    meta:
        description = "Shared family entry-point code clusters for TrojanDownloader_WinPE_Maloader"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { E8 5E 6B 00 00 E9 A5 FE FF FF 6A 0C 68 D0 F1 42 }
        $code_064_1 = { FF FF E8 09 00 00 00 8B 45 E4 E8 31 2C 00 00 C3 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule TrojanDownloader_WinPE_Small
{
    meta:
        description = "Shared family entry-point code clusters for TrojanDownloader_WinPE_Small"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { E8 6B 03 00 00 E9 74 FE FF FF CC CC CC CC CC CC }
        $ep_4 = { 48 83 EC 28 48 8B 05 35 40 00 00 C7 00 00 00 00 }
        $code_048_2 = { 48 83 EC 28 E8 97 1B 00 00 48 85 C0 0F 94 C0 0F }
        $code_160_2 = { 44 24 0C 76 01 4E 33 D2 8B C6 5E 5B C2 10 00 55 }
        $code_240_3 = { 07 B8 01 00 00 00 EB 36 48 8D 0D 21 3A 00 00 48 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_160_2 at (pe.entry_point + 160))
                or ($ep_4 at (pe.entry_point + 0) and $code_048_2 at (pe.entry_point + 48) and $code_240_3 at (pe.entry_point + 240))))
}

rule TrojanDownloader_WinPE_Upatre
{
    meta:
        description = "Shared family entry-point code clusters for TrojanDownloader_WinPE_Upatre"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { E8 13 FD FF FF EB F9 CC 63 00 6E 0C D7 56 14 FC }
        $ep_2 = { 55 8B EC 81 EC 3C 08 00 00 53 56 57 33 F6 56 FF }
        $ep_3 = { E8 87 2B 00 00 E8 6C 20 00 00 F6 1B 50 00 27 2C }
        $ep_4 = { E8 26 02 00 00 C3 00 00 15 00 25 00 00 00 40 BE }
        $ep_5 = { E8 01 00 00 00 C3 55 8B EC 89 2D C6 42 40 00 FF }
        $ep_7 = { 55 8B EC 81 EC 38 08 00 00 53 56 57 33 F6 56 FF }
        $code_016_7 = { 00 A3 14 31 40 00 6A 0A FF 35 14 31 40 00 6A 00 }
        $code_032_1 = { 45 AF 00 50 06 00 B4 0A 6C 00 70 2C 7C 08 05 00 }
        $code_032_4 = { 50 00 F6 32 50 00 64 3A 50 00 1C 3B 50 00 5E 1D }
        $code_032_5 = { 40 40 00 A3 D4 47 40 00 A3 BE 42 40 00 C7 05 C0 }
        $code_032_6 = { 00 BE 25 15 00 00 CC 00 40 00 00 8C 40 2E AC 6D }
        $code_048_3 = { 00 20 40 00 8B 1D 28 20 40 00 57 6A 08 50 89 45 }
        $code_048_8 = { 00 55 8B EC 83 C4 B0 C7 45 D0 30 00 00 00 C7 45 }
        $code_064_1 = { 6F 16 45 EC 68 02 68 6E 04 74 0C 81 63 03 53 6F }
        $code_064_2 = { 6A 08 FF 75 EC 89 45 F4 FF D3 57 FF 75 F4 89 45 }
        $code_064_3 = { FF FF 00 00 00 00 55 8B EC 83 EC 10 EB 07 00 00 }
        $code_064_4 = { FF 75 EC 8B D8 FF 15 2C 20 40 00 57 53 56 89 45 }
        $code_064_6 = { 00 EB 04 00 00 00 00 33 C0 C7 05 C8 47 40 00 16 }
        $code_064_7 = { 00 15 BE 40 40 DC 28 34 40 40 2D 42 2E 40 00 00 }
        $code_080_6 = { 00 00 00 C7 45 E0 00 00 00 00 FF 35 10 31 40 00 }
        $code_128_3 = { 83 C4 10 56 68 80 00 00 00 6A 03 56 6A 01 68 00 }
        $code_192_3 = { FF D7 8B 4D E4 8D 44 41 04 50 6A 08 FF 75 F4 FF }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("wininet.dll", "InternetOpenW") and pe.imports("wininet.dll", "InternetConnectW") and $ep_2 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("wininet.dll", "InternetOpenW") and pe.imports("wininet.dll", "InternetConnectW") and $code_048_3 at (pe.entry_point + 48) and $code_128_3 at (pe.entry_point + 128))
                or ($code_016_7 at (pe.entry_point + 16) and $code_048_8 at (pe.entry_point + 48) and $code_080_6 at (pe.entry_point + 80))
                or (pe.imports("wininet.dll", "InternetOpenW") and pe.imports("wininet.dll", "InternetConnectW") and $ep_7 at (pe.entry_point + 0) and $code_064_4 at (pe.entry_point + 64))
                or ($ep_3 at (pe.entry_point + 0) and $code_032_4 at (pe.entry_point + 32) and $code_064_3 at (pe.entry_point + 64))
                or ($ep_4 at (pe.entry_point + 0) and $code_032_6 at (pe.entry_point + 32) and $code_064_7 at (pe.entry_point + 64))
                or ($ep_5 at (pe.entry_point + 0) and $code_032_5 at (pe.entry_point + 32) and $code_064_6 at (pe.entry_point + 64))
                or (pe.imports("wininet.dll", "InternetOpenW") and pe.imports("wininet.dll", "InternetConnectW") and $code_128_3 at (pe.entry_point + 128) and $code_192_3 at (pe.entry_point + 192))))
}

rule TrojanDownloader_WinPE_Zurgop
{
    meta:
        description = "Shared family entry-point code clusters for TrojanDownloader_WinPE_Zurgop"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { E8 00 00 00 00 75 05 74 03 25 40 0D 5B EB 0A 0C }
        $code_032_1 = { 05 01 41 15 CC 00 6A 30 75 05 74 03 31 D7 5D 58 }
        $code_064_1 = { 41 15 CC 90 20 83 B8 A4 00 00 00 06 7C 4D EB 0C }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule TrojanDropper_MSIL_Agent
{
    meta:
        description = "Shared family entry-point code clusters for TrojanDropper_MSIL_Agent"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { FF 25 00 20 40 00 00 00 00 00 CD CC 4C 3D CD CC }
        $code_016_1 = { FF FF CC CC 48 83 EC 28 E8 43 E8 CE FF EB 02 33 }
        $code_064_1 = { CC 3E 66 66 26 3F CD CC 4C 3F 00 00 80 3F 00 00 }
        $code_128_1 = { D1 89 4D F8 8B F9 89 55 FC 75 5B 48 83 0D 4D C1 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_128_1 at (pe.entry_point + 128))
                or (pe.data_directories[14].size > 0 and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule TrojanDropper_WinPE_Agent
{
    meta:
        description = "Shared family entry-point code clusters for TrojanDropper_WinPE_Agent"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { E8 D8 06 00 00 E9 7A FE FF FF 8B 4D F4 64 89 0D }
        $ep_2 = { E8 5C 00 00 00 A3 0B 30 40 00 6A 00 E8 68 00 00 }
        $ep_3 = { 55 8B EC 6A FF 68 98 31 40 00 68 30 26 40 00 64 }
        $ep_4 = { 55 8B EC 83 C4 F0 B8 B0 55 48 00 E8 C8 0E F8 FF }
        $ep_5 = { 55 8B EC 83 C4 D4 53 56 57 33 C0 89 45 F0 89 45 }
        $ep_6 = { 55 8B EC 6A FF 68 A0 C6 41 00 68 F0 89 41 00 64 }
        $ep_7 = { 55 8B EC 6A FF 68 A0 A1 40 00 68 A2 9B 40 00 64 }
        $ep_9 = { 55 8B EC 83 C4 CC 53 56 57 33 C0 89 45 F0 89 45 }
        $ep_10 = { 55 8B EC 6A FF 68 38 01 41 00 68 F0 B6 40 00 64 }
        $code_048_7 = { 00 00 50 E8 3F 01 00 00 83 C4 04 B8 00 00 03 00 }
        $code_064_1 = { 89 28 8B E8 A1 1C 30 69 00 33 C5 50 FF 75 FC C7 }
        $code_064_2 = { 20 40 00 FF 25 08 20 40 00 FF 25 0C 20 40 00 FF }
        $code_064_3 = { 00 FF FF 15 5C 31 40 00 8B 0D 10 45 40 00 89 08 }
        $code_064_4 = { CC 7B 48 00 8B 00 C6 40 5B 00 A1 CC 7B 48 00 8B }
        $code_064_5 = { 89 20 33 D2 55 68 BB 9E 40 00 64 FF 32 64 89 22 }
        $code_064_7 = { 00 FF FF 15 E8 A1 41 00 8B 0D 74 0A 42 00 89 08 }
        $code_064_8 = { 00 FF FF 15 C8 A0 40 00 8B 0D 8C F8 70 00 89 08 }
        $code_064_9 = { DC 90 41 00 C1 E1 08 03 CA 89 0D D8 90 41 00 C1 }
        $code_064_10 = { 68 50 9E 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 }
        $code_064_11 = { 50 B8 00 00 01 00 50 E8 3B 01 00 00 83 C4 08 8B }
        $code_096_4 = { F0 00 00 00 00 C7 45 F4 00 00 00 00 EB 39 8B 55 }
        $code_096_9 = { 01 89 45 F8 8D 45 FC 50 8B 05 00 00 08 01 50 52 }
        $code_128_4 = { 55 F4 8B 45 08 01 D0 0F B6 08 8B 45 F8 89 C3 8B }
        $code_160_5 = { 89 45 F8 83 45 F4 01 8B 45 F4 3B 45 0C 7C BF 90 }
        $code_160_6 = { FE FF FF 83 C4 0C 50 E8 E3 00 00 00 83 C4 04 C9 }
        $code_160_10 = { FE FF FF 83 C4 0C 50 E8 EB 00 00 00 83 C4 04 C9 }
        $code_160_13 = { 00 C9 13 00 00 ED 05 00 00 00 08 00 66 72 6D 4C }
        $code_192_8 = { FF C0 FF 00 04 FF C0 FF 00 0A 01 19 00 00 00 00 }
        $code_208_5 = { 08 B8 00 00 03 00 50 B8 00 00 01 00 50 E8 9D 00 }
        $code_224_7 = { 22 03 23 86 05 00 00 6C 74 00 00 7E 05 00 00 00 }
    condition:
        (General_WinPE_AnySizePE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_3 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_5 at (pe.entry_point + 0) and $code_064_5 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_064_4 at (pe.entry_point + 64))
                or ($code_096_4 at (pe.entry_point + 96) and $code_128_4 at (pe.entry_point + 128) and $code_160_5 at (pe.entry_point + 160))
                or (pe.imports("ws2_32.dll", "WSAStartup") and pe.imports("ws2_32.dll", "connect") and $ep_7 at (pe.entry_point + 0) and $code_064_8 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or ($code_048_7 at (pe.entry_point + 48) and $code_160_6 at (pe.entry_point + 160) and $code_208_5 at (pe.entry_point + 208))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_6 at (pe.entry_point + 0) and $code_064_7 at (pe.entry_point + 64))
                or ($code_160_13 at (pe.entry_point + 160) and $code_192_8 at (pe.entry_point + 192) and $code_224_7 at (pe.entry_point + 224))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_9 at (pe.entry_point + 0) and $code_064_10 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_10 at (pe.entry_point + 0) and $code_064_9 at (pe.entry_point + 64))
                or ($code_064_11 at (pe.entry_point + 64) and $code_096_9 at (pe.entry_point + 96) and $code_160_10 at (pe.entry_point + 160))))
}

rule TrojanDropper_WinPE_Gepys
{
    meta:
        description = "Shared family entry-point code clusters for TrojanDropper_WinPE_Gepys"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 81 EC 14 02 00 00 56 C7 05 04 E3 42 00 }
        $code_064_1 = { 42 00 8E 00 00 00 8B 4D 08 89 0D 18 E3 42 00 C7 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule TrojanSpy_MSIL_AgentTesla
{
    meta:
        description = "Shared family entry-point code clusters for TrojanSpy_MSIL_AgentTesla"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_20 = { FF 25 00 20 40 00 8F C2 F5 BC CD CC 4C 3D 0A D7 }
        $ep_39 = { FF 25 00 20 40 00 1C 42 84 2B 90 A2 CB 3F 94 ED }
        $code_064_5 = { 7E D5 C9 80 8E 40 C8 AD 9C 52 77 0A C4 40 AD 87 }
        $code_080_4 = { 83 BC 6F 12 83 BC F2 D2 BD 3F 00 00 00 00 00 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.data_directories[14].size > 0 and $ep_20 at (pe.entry_point + 0) and $code_080_4 at (pe.entry_point + 80))
                or (pe.data_directories[14].size > 0 and $ep_39 at (pe.entry_point + 0) and $code_064_5 at (pe.entry_point + 64))))
}

rule TrojanSpy_MSIL_Stealer
{
    meta:
        description = "Shared family entry-point code clusters for TrojanSpy_MSIL_Stealer"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_3 = { FF 25 00 20 40 00 00 00 00 00 CD CC CC 3D 9A 99 }
        $code_064_1 = { 80 3F 33 33 33 3F 00 00 00 3F CD CC 4C 3E 00 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.data_directories[14].size > 0 and $ep_3 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule TrojanSpy_Win64_Banker
{
    meta:
        description = "Shared family entry-point code clusters for TrojanSpy_Win64_Banker"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 48 89 5C 24 20 55 56 57 41 54 41 55 41 56 41 57 }
        $code_032_1 = { BE 07 00 48 33 C4 48 89 45 18 0F 57 C0 4C 89 44 }
        $code_064_1 = { C2 00 00 CC 48 83 61 10 00 48 8D 05 D0 29 00 00 }
        $code_064_2 = { 4C 24 58 E8 F0 E9 03 00 84 C0 0F 84 C5 04 00 00 }
        $code_064_3 = { C2 00 00 CC 48 83 61 10 00 48 8D 05 D0 28 00 00 }
        $code_112_1 = { FF FF 48 8D 15 9F 3B 00 00 48 8D 4C 24 20 E8 8B }
        $code_112_3 = { FF FF 48 8D 15 97 CB 00 00 48 8D 4C 24 20 E8 8B }
        $code_112_4 = { FF FF 48 8D 15 97 D0 00 00 48 8D 4C 24 20 E8 8B }
        $code_128_2 = { 48 83 EC 28 E8 9F 07 00 00 85 C0 74 21 65 48 8B }
        $code_224_1 = { F3 54 00 00 FF 25 F0 3F FF 0F 3D C0 06 01 00 74 }
        $code_224_3 = { F3 E3 00 00 FF 25 F0 3F FF 0F 3D C0 06 01 00 74 }
        $code_224_4 = { 02 00 00 84 C0 75 04 32 C0 EB 14 E8 B0 02 00 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_064_1 at (pe.entry_point + 64) and $code_112_1 at (pe.entry_point + 112) and $code_224_1 at (pe.entry_point + 224))
                or ($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_2 at (pe.entry_point + 64))
                or ($code_064_3 at (pe.entry_point + 64) and $code_112_3 at (pe.entry_point + 112) and $code_224_3 at (pe.entry_point + 224))
                or ($code_064_3 at (pe.entry_point + 64) and $code_112_4 at (pe.entry_point + 112) and $code_224_3 at (pe.entry_point + 224))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_128_2 at (pe.entry_point + 128) and $code_224_4 at (pe.entry_point + 224))))
}

rule TrojanSpy_WinPE_Agent
{
    meta:
        description = "Shared family entry-point code clusters for TrojanSpy_WinPE_Agent"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 55 57 B8 2C 80 00 00 56 53 E8 C2 8F 01 00 29 C4 }
        $code_016_2 = { 53 56 57 FF 35 C8 B3 8C 00 E8 73 1A 00 00 FF 35 }
        $code_064_1 = { FF FF FF C7 44 24 08 04 00 00 00 89 74 24 04 89 }
        $code_144_2 = { 8D 34 98 E8 7E 19 00 00 59 A3 C8 B3 8C 00 FF 75 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_2 at (pe.entry_point + 16) and $code_144_2 at (pe.entry_point + 144))))
}

rule TrojanSpy_WinPE_Banker
{
    meta:
        description = "Shared family entry-point code clusters for TrojanSpy_WinPE_Banker"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 83 7D 0C 01 75 05 E8 F2 1E 01 00 8B 45 }
        $ep_2 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 3F 46 00 00 }
        $ep_3 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 A7 5E 00 00 }
        $ep_4 = { 89 E0 A3 30 39 43 00 E8 F6 D2 FF FF 89 45 FC 55 }
        $ep_5 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 FD 3D 00 00 }
        $ep_6 = { 8D 05 AD 18 40 00 FF D0 40 C3 89 45 FC 55 89 E5 }
        $ep_7 = { 83 7C 24 08 01 75 05 E8 51 4C 00 00 FF 74 24 04 }
        $ep_8 = { 55 8B EC 83 7D 0C 01 75 05 E8 0A 9B 00 00 FF 75 }
        $code_032_3 = { 8C C7 45 EC BD A0 2E 7C 8A 5D F3 88 DF 80 F7 FF }
        $code_032_5 = { C7 45 F0 79 88 95 2A 89 4D 84 89 55 80 89 85 7C }
        $code_032_6 = { C2 0C 00 6A 0C 68 78 43 04 01 E8 69 4F 00 00 33 }
        $code_032_7 = { C2 0C 00 55 8B EC 6A 00 FF 15 54 C0 02 10 FF 75 }
        $code_064_1 = { 05 01 33 C5 89 45 FC 83 A5 D8 FC FF FF 00 53 6A }
        $code_064_2 = { A1 00 00 00 00 50 83 C4 E8 53 56 57 A1 5C 97 04 }
        $code_064_3 = { FF FF 8B 85 7C FF FF FF B9 62 65 CF 14 2B 4D F4 }
        $code_064_4 = { 7C 1C 05 01 E9 D4 3E 00 00 8B FF 55 8B EC 56 8B }
        $code_064_5 = { 04 00 00 00 00 89 85 78 FF FF FF E8 A1 F9 FF FF }
        $code_064_6 = { E9 1C 4D 00 00 56 8B F1 C7 06 54 4F 05 01 E8 0E }
        $code_080_8 = { 02 75 35 8B 0D 80 D7 03 01 85 C9 74 0C FF 75 10 }
        $code_096_5 = { 02 59 CD 29 A3 C8 99 03 10 89 0D C4 99 03 10 89 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or ($ep_4 at (pe.entry_point + 0) and $code_032_3 at (pe.entry_point + 32) and $code_064_3 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_5 at (pe.entry_point + 0) and $code_064_4 at (pe.entry_point + 64))
                or ($ep_6 at (pe.entry_point + 0) and $code_032_5 at (pe.entry_point + 32) and $code_064_5 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_7 at (pe.entry_point + 0) and $code_064_6 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_7 at (pe.entry_point + 32) and $code_096_5 at (pe.entry_point + 96))
                or ($ep_8 at (pe.entry_point + 0) and $code_032_6 at (pe.entry_point + 32) and $code_080_8 at (pe.entry_point + 80))))
}

rule TrojanSpy_WinPE_CoinStealer
{
    meta:
        description = "Shared family entry-point code clusters for TrojanSpy_WinPE_CoinStealer"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { E8 0C 58 00 00 E9 89 FE FF FF 8B FF 55 8B EC 83 }
        $code_064_1 = { 45 F4 50 FF 75 F0 FF 75 E4 FF 75 E0 FF 15 68 50 }
        $code_160_1 = { 89 75 FC C7 45 F8 56 A2 40 00 6A 00 FF 75 0C FF }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64) and $code_160_1 at (pe.entry_point + 160))))
}

rule TrojanSpy_WinPE_Fareit
{
    meta:
        description = "Shared family entry-point code clusters for TrojanSpy_WinPE_Fareit"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 5D 68 2F 06 41 00 F8 72 01 C3 FF E8 54 }
        $code_064_1 = { 81 41 00 FF 25 54 81 41 00 FF 25 58 81 41 00 FF }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule TrojanSpy_WinPE_GameSpy
{
    meta:
        description = "Shared family entry-point code clusters for TrojanSpy_WinPE_GameSpy"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 6A FF 68 E0 55 4D 00 68 34 DD 49 00 64 }
        $ep_2 = { 60 BE 00 00 61 00 8D BE 00 10 DF FF 57 83 CD FF }
        $ep_3 = { 60 BE 00 F0 60 00 8D BE 00 20 DF FF 57 83 CD FF }
        $code_016_1 = { F6 75 09 83 3D 08 D3 01 10 00 EB 26 83 FE 01 74 }
        $code_016_2 = { EC 28 03 00 00 A3 88 20 41 00 89 0D 84 20 41 00 }
        $code_064_1 = { B0 3C 52 00 C1 E1 08 03 CA 89 0D AC 3C 52 00 C1 }
        $code_080_2 = { 6C 20 41 00 66 8C 25 68 20 41 00 66 8C 2D 64 20 }
        $code_160_2 = { 41 01 10 FF 25 50 41 01 10 FF 25 48 41 01 10 CC }
        $code_192_1 = { 24 48 8B 44 24 44 8B 54 24 3C 56 57 8B 7C 24 48 }
        $code_208_2 = { FF FF 5E 89 F7 B9 23 00 00 00 8A 07 47 2C E8 3C }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_208_2 at (pe.entry_point + 208))
                or ($code_016_1 at (pe.entry_point + 16) and $code_160_2 at (pe.entry_point + 160) and $code_192_1 at (pe.entry_point + 192))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_208_2 at (pe.entry_point + 208))
                or (pe.imports("advapi32.dll", "OpenSCManagerA") and pe.imports("advapi32.dll", "CreateServiceA") and $code_016_2 at (pe.entry_point + 16) and $code_080_2 at (pe.entry_point + 80))))
}

rule TrojanSpy_WinPE_PassStealer
{
    meta:
        description = "Shared family entry-point code clusters for TrojanSpy_WinPE_PassStealer"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 60 BE 00 10 67 01 8D BE 00 00 D9 FE 57 83 CD FF }
        $ep_2 = { 55 8B EC 83 C4 C4 B8 58 AA 41 00 E8 98 B8 FE FF }
        $code_064_1 = { 24 1C C7 44 24 08 04 00 00 00 89 74 24 04 C7 44 }
        $code_064_2 = { DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 48 01 }
        $code_144_1 = { 00 00 84 C0 74 60 8B 4C 24 18 81 F9 FF 7F 00 00 }
        $code_208_4 = { 00 00 00 00 80 23 40 00 2C 25 40 00 08 29 40 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_064_1 at (pe.entry_point + 64) and $code_144_1 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_208_4 at (pe.entry_point + 208))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))))
}

rule TrojanSpy_WinPE_QQPass
{
    meta:
        description = "Shared family entry-point code clusters for TrojanSpy_WinPE_QQPass"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { E8 5B C2 03 00 E8 B0 A9 03 00 33 C0 C3 90 90 90 }
        $code_160_1 = { 01 45 FC 89 07 83 C7 04 49 75 E9 FF 75 FC E8 6A }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_160_1 at (pe.entry_point + 160))))
}

rule TrojanSpy_WinPE_Stealer
{
    meta:
        description = "Shared family entry-point code clusters for TrojanSpy_WinPE_Stealer"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_2 = { FF 25 00 20 40 00 51 F4 A7 50 7E 41 65 53 1A 17 }
        $ep_3 = { E8 EE 31 00 00 E9 A4 FE FF FF 8B FF 55 8B EC 8B }
        $ep_4 = { E8 31 1C 00 00 E9 89 FE FF FF 8B FF 55 8B EC 81 }
        $ep_5 = { E8 12 7A 00 00 E9 89 FE FF FF 8B FF 55 8B EC 83 }
        $ep_6 = { E8 02 75 00 00 E9 A4 FE FF FF 3B 0D 90 D6 43 00 }
        $ep_8 = { 55 48 83 EC 20 48 8B EC 90 48 8D 0D 08 F0 FE FF }
        $code_016_1 = { 01 3C 22 75 28 41 8A 11 84 D2 74 11 8A C2 8A D0 }
        $code_016_2 = { 8B 05 84 D9 01 00 C7 00 01 00 00 00 E8 3D 00 00 }
        $code_064_3 = { 44 80 B5 62 A3 8F DE B1 5A 49 25 BA 1B 67 45 EA }
        $code_064_4 = { 8B 15 2A E9 FE FF 4C 8B 05 C3 E5 05 00 E8 3E 38 }
        $code_064_5 = { 59 3B C8 1B C0 23 C1 83 C0 08 5D C3 E8 B5 24 00 }
        $code_064_6 = { 48 83 61 10 00 48 8D 05 98 ED 02 00 48 89 41 08 }
        $code_064_7 = { 45 F4 50 FF 75 F0 FF 75 E4 FF 75 E0 FF 15 B4 70 }
        $code_080_1 = { E8 00 8D 45 BC 50 FF 15 40 41 41 00 E8 2D 00 00 }
        $code_096_4 = { 28 8B E8 A1 90 D6 43 00 33 C5 50 89 65 F0 FF 75 }
        $code_096_5 = { 00 A3 08 12 43 00 89 0D 04 12 43 00 89 15 00 12 }
        $code_128_3 = { 8B 02 03 01 89 01 41 33 01 C1 C0 10 41 89 01 41 }
        $code_176_2 = { E6 22 03 00 FF D0 48 8B 05 2D D9 01 00 48 89 45 }
        $code_192_3 = { 41 55 41 54 55 57 56 53 48 81 EC 88 04 00 00 4C }
        $code_208_7 = { 4C 24 08 89 54 24 0C 75 50 48 83 0D CB A1 05 00 }
        $code_240_8 = { 00 00 75 08 6A 01 E8 D6 1B 00 00 59 68 09 04 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_2 at (pe.entry_point + 16) and $code_176_2 at (pe.entry_point + 176))
                or (pe.data_directories[14].size > 0 and $ep_2 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_128_3 at (pe.entry_point + 128) and $code_192_3 at (pe.entry_point + 192))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_5 at (pe.entry_point + 64))
                or ($ep_5 at (pe.entry_point + 0) and $code_064_7 at (pe.entry_point + 64) and $code_096_5 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_6 at (pe.entry_point + 0) and $code_096_4 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_064_6 at (pe.entry_point + 64) and $code_208_7 at (pe.entry_point + 208))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_8 at (pe.entry_point + 0) and $code_064_4 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_240_8 at (pe.entry_point + 240))))
}

rule TrojanSpy_WinPE_Ursnif
{
    meta:
        description = "Shared family entry-point code clusters for TrojanSpy_WinPE_Ursnif"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 51 8B 45 0C 53 56 57 33 FF 47 33 DB 2B }
        $ep_3 = { 55 8B EC E8 08 18 01 00 E8 03 00 00 00 5D C3 CC }
        $ep_4 = { 55 8B EC 51 8B 45 0C 53 56 33 DB 57 43 33 FF 2B }
        $code_064_1 = { 10 41 00 10 74 3E 8B 45 08 BE 18 41 00 10 A3 30 }
        $code_080_1 = { 41 00 10 8B C6 F0 0F C1 38 8B 4D 10 8D 45 0C 50 }
        $code_128_2 = { 8D 45 98 50 FF 15 3C 14 40 00 C7 45 FC FE FF FF }
        $code_224_1 = { A9 F8 FF FF 81 FE FF 04 00 00 76 01 40 81 FE FF }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_224_1 at (pe.entry_point + 224))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_128_2 at (pe.entry_point + 128))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_080_1 at (pe.entry_point + 80))))
}

rule Trojan_BAT_Agent
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_BAT_Agent"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples containing batch-script artifacts or payloads; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 55 8B EC 83 7D 0C 01 75 05 E8 53 0C 00 00 FF 75 }
        $code_112_1 = { EB F9 E9 48 AA 03 00 55 8B EC 8B 45 08 85 C0 74 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_112_1 at (pe.entry_point + 112))))
}

rule Trojan_BAT_Runner
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_BAT_Runner"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples containing batch-script artifacts or payloads; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { E8 C5 38 00 00 E9 95 FE FF FF E8 AB 39 00 00 85 }
        $ep_2 = { E8 E7 06 00 00 E9 74 FE FF FF 55 8B EC 83 25 C0 }
        $code_064_1 = { 8B EC 8B 4D 0C A1 D4 B6 42 00 8B 55 08 23 55 0C }
        $code_064_2 = { 57 89 1D C0 19 42 00 8D 7D DC 53 0F A2 8B F3 5B }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))))
}

rule Trojan_MSIL_Agent
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_MSIL_Agent"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_2 = { 48 83 EC 28 E8 A3 FE FF FF 45 33 C9 45 33 C0 33 }
        $code_032_1 = { 08 57 48 83 EC 20 48 8B F9 48 89 11 48 8B CA 48 }
        $code_064_1 = { 00 48 8B 5C 24 30 89 47 10 48 8B C7 48 83 C4 20 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_2 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule Trojan_MSIL_Obfuscated
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_MSIL_Obfuscated"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $code_144_2 = { 00 00 28 89 00 06 29 89 00 06 2A 89 00 06 2B 89 }
        $code_208_1 = { 00 06 38 89 00 06 39 89 00 06 3A 89 00 06 3B 89 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.data_directories[14].size > 0 and $code_144_2 at (pe.entry_point + 144) and $code_208_1 at (pe.entry_point + 208))))
}

rule Trojan_NSIS_Injector
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_NSIS_Injector"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples containing NSIS installer or payload artifacts; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 81 EC EC 03 00 00 53 55 56 57 33 DB BF F0 84 40 }
        $code_032_1 = { 40 00 8B 35 A4 80 40 00 8D 44 24 2C 0F 57 C0 89 }
        $code_160_1 = { 38 96 42 00 0F B6 44 24 30 66 C1 E0 08 0F B7 C8 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_160_1 at (pe.entry_point + 160))))
}

rule Trojan_Win64_Agent
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_Win64_Agent"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 55 56 50 48 89 E5 83 3D CB 2E 0D 00 0A 7C 13 8B }
        $ep_2 = { 44 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 81 }
        $code_032_1 = { EB FE B8 40 00 00 00 E8 F4 8A 06 00 48 29 C4 48 }
        $code_032_2 = { 8D 0D 62 5D 00 00 FF 15 2C 5A 00 00 66 89 84 24 }
        $code_048_3 = { 48 89 5C 24 30 48 89 74 24 38 48 89 7C 24 20 E8 }
        $code_064_1 = { 00 00 00 89 C1 FF 15 E1 3C 0D 00 83 3D 7E 2E 0D }
        $code_064_2 = { C6 44 24 40 47 0F BF 44 24 44 05 ED 03 00 00 66 }
        $code_080_3 = { 00 00 33 DB 8B FB 48 85 C0 74 49 4C 8B 48 18 4D }
        $code_112_3 = { C1 74 31 44 8B C3 48 8B 50 20 48 85 D2 74 05 83 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))
                or ($ep_2 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_064_2 at (pe.entry_point + 64))
                or ($code_048_3 at (pe.entry_point + 48) and $code_080_3 at (pe.entry_point + 80) and $code_112_3 at (pe.entry_point + 112))))
}

rule Trojan_Win64_Bazar
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_Win64_Bazar"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 48 83 EC 10 83 FA 01 B8 40 11 66 A1 BA 64 B7 48 }
        $ep_2 = { 8B 05 FB 9B 00 00 44 8D 48 FF 44 0F AF C8 44 8B }
        $ep_3 = { 41 B9 01 00 00 00 4C 8B C1 41 3B D1 0F 85 AB 00 }
        $code_032_1 = { DA CF 13 86 74 4A 3D 64 B7 48 21 74 47 3D 40 11 }
        $code_032_2 = { C0 41 83 F8 0A 41 0F 9C C2 41 08 C2 8B 05 DB 9B }
        $code_032_3 = { 24 10 41 BB 03 00 00 80 8B 44 24 10 41 23 C3 41 }
        $code_064_1 = { F2 0F 2A 04 24 F2 0F 11 44 24 08 48 89 0D D8 8F }
        $code_064_3 = { 83 FB 0A 7C 0B 8D 50 FF 0F AF D0 83 E2 01 75 26 }
        $code_064_4 = { 24 10 75 07 03 C2 6B C0 07 EB 17 41 23 C3 83 F8 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))
                or ($ep_2 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_064_3 at (pe.entry_point + 64))
                or ($ep_3 at (pe.entry_point + 0) and $code_032_3 at (pe.entry_point + 32) and $code_064_4 at (pe.entry_point + 64))))
}

rule Trojan_Win64_Emotet
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_Win64_Emotet"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_016_1 = { EC 02 00 E8 98 FC FF FF 90 90 48 83 C4 28 C3 90 }
        $code_096_1 = { 48 63 D0 48 8B 45 F8 49 89 D0 48 8B 55 10 48 89 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_096_1 at (pe.entry_point + 96))))
}

rule Trojan_Win64_Injector
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_Win64_Injector"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 46 08 8D 0C 38 EB 07 80 38 0A 75 01 47 40 3B C1 }
        $ep_3 = { 48 83 EC 28 48 8B 05 C5 52 07 00 C7 00 01 00 00 }
        $ep_8 = { 48 83 EC 28 48 8B 05 F5 51 00 00 C7 00 01 00 00 }
        $code_048_1 = { 44 03 10 89 0D 0C 44 03 10 89 15 08 44 03 10 89 }
        $code_048_4 = { 23 03 10 89 0D 0C 23 03 10 89 15 08 23 03 10 89 }
        $code_048_6 = { 15 74 62 02 10 6A 01 6A 00 6A 00 FF 75 FC E8 9C }
        $code_048_7 = { 15 5C 62 02 10 6A 01 6A 00 6A 00 FF 75 FC E8 3C }
        $code_048_8 = { 43 03 10 89 0D 0C 43 03 10 89 15 08 43 03 10 89 }
        $code_048_9 = { 15 24 32 02 10 6A 01 6A 00 6A 00 FF 75 FC E8 E9 }
        $code_064_5 = { 00 E8 9A B5 03 00 E8 75 FC FF FF 90 90 48 83 C4 }
        $code_096_2 = { 00 00 74 03 8B 7E 18 8B 85 E4 EF FF FF 8B 00 F6 }
        $code_112_1 = { F0 43 03 10 66 8C 2D EC 43 03 10 9C 8F 05 20 44 }
        $code_112_3 = { F0 22 03 10 66 8C 2D EC 22 03 10 9C 8F 05 20 23 }
        $code_112_4 = { 8D 45 F8 50 FF 15 74 62 02 10 6A 01 6A 00 6A 00 }
        $code_112_5 = { 8D 45 F8 50 FF 15 5C 62 02 10 6A 01 6A 00 6A 00 }
        $code_112_6 = { F0 42 03 10 66 8C 2D EC 42 03 10 9C 8F 05 20 43 }
        $code_112_7 = { 8D 45 F8 50 FF 15 24 32 02 10 6A 01 6A 00 6A 00 }
        $code_112_8 = { 55 41 57 41 56 41 55 41 54 56 57 53 48 81 EC E8 }
        $code_128_2 = { D1 EF 29 BD EC EF FF FF 83 9D F0 EF FF FF 00 80 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_048_1 at (pe.entry_point + 48) and $code_112_1 at (pe.entry_point + 112))
                or ($ep_1 at (pe.entry_point + 0) and $code_096_2 at (pe.entry_point + 96) and $code_128_2 at (pe.entry_point + 128))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_5 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_048_4 at (pe.entry_point + 48) and $code_112_3 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_048_7 at (pe.entry_point + 48) and $code_112_5 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_048_6 at (pe.entry_point + 48) and $code_112_4 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_048_8 at (pe.entry_point + 48) and $code_112_6 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_8 at (pe.entry_point + 0) and $code_112_8 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_048_9 at (pe.entry_point + 48) and $code_112_7 at (pe.entry_point + 112))))
}

rule Trojan_Win64_Loader
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_Win64_Loader"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 41 57 41 56 56 57 53 48 83 EC 20 4C 89 C7 41 89 }
        $code_016_1 = { 74 76 48 8B 3D 67 5E 1A 00 89 17 85 D2 0F 85 CD }
        $code_016_2 = { 74 76 48 8B 3D 67 4E 1A 00 89 17 85 D2 0F 85 CD }
        $code_064_1 = { 46 FF 83 F8 01 77 16 48 89 D9 44 89 F2 49 89 F8 }
        $code_080_2 = { 48 89 0D 69 AC 00 00 C3 49 89 CA 4C 8B 1D 5E AC }
        $code_128_3 = { 45 31 D2 EB C9 0F 1F 00 48 8B 05 01 5E 1A 00 48 }
        $code_128_4 = { 45 31 D2 EB C9 0F 1F 00 48 8B 05 01 4E 1A 00 48 }
        $code_144_2 = { 4F 8D 14 DA 49 89 1A 4C 8D 15 42 AD 00 00 4F 8D }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_080_2 at (pe.entry_point + 80) and $code_144_2 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_128_3 at (pe.entry_point + 128))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_2 at (pe.entry_point + 16) and $code_128_4 at (pe.entry_point + 128))))
}

rule Trojan_WinPE_Agent
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Agent"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 68 D4 3E 40 00 E8 F0 FF FF FF 00 00 40 00 00 00 }
        $ep_2 = { 8B FF 55 8B EC E8 E6 13 00 00 E8 11 00 00 00 5D }
        $ep_3 = { FE C1 8D 1D B4 31 E2 DC 86 DD 0F BE F7 80 EB 38 }
        $ep_4 = { EB 03 C2 0C 00 55 8B EC 81 EC 00 10 00 00 B8 00 }
        $ep_8 = { 57 56 53 51 E8 54 F4 FF FF C3 68 00 00 03 00 68 }
        $code_032_2 = { 80 67 13 47 B1 52 93 58 73 8B 90 04 00 00 00 00 }
        $code_032_5 = { 48 83 EC 28 E8 E7 07 00 00 85 C0 74 21 65 48 8B }
        $code_032_6 = { 23 4D 89 DD 0F BF EA 0A F8 F6 C1 8C 8D 05 DF 8D }
        $code_064_2 = { 2D B9 32 00 00 BF 1D F2 60 F7 8B DD 8D 08 85 F5 }
        $code_064_4 = { 74 03 C9 FF E0 8B 45 84 03 85 50 FF FF FF 89 85 }
        $code_064_5 = { 10 43 00 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 }
        $code_064_6 = { 00 43 00 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 }
        $code_064_7 = { A1 7A 40 40 00 50 8D 15 50 1F 40 00 52 B8 3D 00 }
        $code_080_3 = { A8 4F 01 00 48 BB 32 A2 DF 2D 99 2B 00 00 48 3B }
        $code_080_5 = { 8D 3D EA 49 16 00 EB 12 48 8B 03 48 85 C0 74 06 }
        $code_096_1 = { 85 4E F1 7E B1 9C 9A 4B 98 C2 C9 F7 1A 70 A9 38 }
        $code_112_2 = { 00 6A 00 6A 01 6A 00 FF 15 4C 11 40 00 E8 8E 01 }
        $code_112_4 = { 01 00 48 8B 45 18 48 89 45 10 FF 15 14 29 01 00 }
        $code_112_5 = { 8B 0F E9 A9 FF FF FF 00 00 40 40 FF FF E8 5E FF }
        $code_112_6 = { 5D C3 55 53 48 81 EC 28 0A 00 00 48 8D AC 24 80 }
        $code_128_3 = { 00 00 89 45 94 E8 36 4B 00 00 85 C0 75 0A 6A 1C }
        $code_128_7 = { 18 00 00 84 C0 75 04 32 C0 EB 14 E8 48 73 00 00 }
        $code_144_6 = { 4D 20 48 31 45 10 FF 15 D8 29 01 00 8B 45 20 48 }
        $code_144_8 = { 00 CC CC CC 48 83 EC 28 E8 0B 00 00 00 EB 02 33 }
        $code_208_6 = { 8B 85 C8 09 00 00 48 89 85 98 09 00 00 48 8B 85 }
        $code_224_6 = { CC 11 00 00 A3 C4 1F 43 00 E8 D2 0D 00 00 85 C0 }
        $code_224_7 = { CC 11 00 00 A3 C4 0F 43 00 E8 D2 0D 00 00 85 C0 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_096_1 at (pe.entry_point + 96))
                or ($ep_3 at (pe.entry_point + 0) and $code_032_6 at (pe.entry_point + 32) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_112_2 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_064_4 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_5 at (pe.entry_point + 32) and $code_128_7 at (pe.entry_point + 128))
                or ($code_080_3 at (pe.entry_point + 80) and $code_112_4 at (pe.entry_point + 112) and $code_144_6 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_064_5 at (pe.entry_point + 64) and $code_224_6 at (pe.entry_point + 224))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_064_6 at (pe.entry_point + 64) and $code_224_7 at (pe.entry_point + 224))
                or ($ep_8 at (pe.entry_point + 0) and $code_064_7 at (pe.entry_point + 64) and $code_112_5 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_112_6 at (pe.entry_point + 112) and $code_208_6 at (pe.entry_point + 208))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_080_5 at (pe.entry_point + 80) and $code_144_8 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_128_3 at (pe.entry_point + 128))))
}

rule Trojan_WinPE_Bancteian
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Bancteian"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_016_1 = { 6A 00 E8 4D 20 F5 FF 33 C9 66 BA 01 00 E8 56 0D }
        $code_096_1 = { FC F3 FF A1 C8 4C 69 00 8B 00 E8 B1 FD F3 FF E8 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_096_1 at (pe.entry_point + 96))))
}

rule Trojan_WinPE_CoinMiner
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_CoinMiner"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 55 8B EC 6A FF 68 F0 94 18 01 68 C4 8C 46 00 64 }
        $ep_2 = { 48 83 EC 28 48 8B 05 B5 3A A3 00 C7 00 00 00 00 }
        $code_032_1 = { 53 56 57 89 65 E8 FF 15 9C 71 48 00 33 D2 8A D4 }
        $code_032_2 = { C2 0C 00 3B 0D F0 7B B6 37 F2 75 02 F2 C3 F2 E9 }
        $code_064_1 = { B0 2E 1D 01 C1 E1 08 03 CA 89 0D AC 2E 1D 01 C1 }
        $code_096_2 = { 56 57 89 28 8B E8 A1 F0 7B B6 37 33 C5 50 FF 75 }
        $code_096_3 = { 48 83 EC 38 48 8B 05 A5 32 A3 00 48 8B 0D 6E 4B }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_2 at (pe.entry_point + 32) and $code_096_2 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_096_3 at (pe.entry_point + 96))))
}

rule Trojan_WinPE_ConvertMate
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_ConvertMate"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 48 83 EC 28 E8 0F 05 00 00 48 83 C4 28 E9 72 FE }
        $code_144_2 = { C2 01 74 0A BA 18 00 00 00 E8 2A 08 00 00 48 8B }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_144_2 at (pe.entry_point + 144))))
}

rule Trojan_WinPE_Coroxy
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Coroxy"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 81 C4 FC FB FF FF 8D 4D 00 2B CC 51 8D }
        $code_064_1 = { 0B C0 74 1F 64 A1 30 00 00 00 8B 40 0C 8B 40 0C }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("wsock32.dll", "WSAStartup") and pe.imports("wsock32.dll", "connect") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Trojan_WinPE_Crypt
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Crypt"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 6A FF 68 A8 80 40 00 68 90 4A 40 00 64 }
        $code_032_2 = { 53 56 57 89 65 E8 FF 15 14 60 40 00 33 D2 8A D4 }
        $code_064_1 = { A8 20 4A 00 C1 E1 08 03 CA 89 0D A4 20 4A 00 C1 }
        $code_160_2 = { 15 0C 60 40 00 E8 CD 03 00 00 89 45 9C F6 45 D0 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_2 at (pe.entry_point + 32) and $code_160_2 at (pe.entry_point + 160))))
}

rule Trojan_WinPE_DonutLoader
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_DonutLoader"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 48 83 EC 28 E8 AB 06 00 00 48 83 C4 28 E9 72 FE }
        $code_080_1 = { 8B F9 75 5E 25 F0 3F FF 0F 48 C7 05 4C B1 00 00 }
        $code_160_1 = { 05 0B BB 00 00 41 83 C8 01 44 89 05 00 BB 00 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_080_1 at (pe.entry_point + 80) and $code_160_1 at (pe.entry_point + 160))))
}

rule Trojan_WinPE_Dorv
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Dorv"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 68 3C 00 00 00 68 00 00 00 00 68 E0 0E 42 00 E8 }
        $code_064_1 = { 00 F2 41 00 A3 F0 0E 42 00 E8 92 5B 01 00 E8 2D }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Trojan_WinPE_Dridex
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Dridex"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_2 = { 48 C7 C0 01 00 00 00 48 09 0D B2 14 07 00 48 8D }
        $ep_5 = { BA 03 00 00 00 0F C2 C8 02 83 C0 0C 83 C0 0C 83 }
        $ep_9 = { 40 BA 03 00 00 00 0F C2 C8 02 83 FA 03 0F 84 1D }
        $ep_10 = { 31 C0 E9 B9 D2 FF FF 40 CC CC CC CC CC CC CC CC }
        $ep_12 = { 55 8B EC 83 EC 10 C7 45 F8 01 00 00 00 C7 45 FC }
        $code_016_6 = { 55 89 E5 56 57 53 83 E4 F8 81 EC D8 00 00 00 0F }
        $code_016_8 = { 55 89 E5 57 53 56 83 E4 F8 81 EC F0 00 00 00 C7 }
        $code_032_3 = { 09 35 EA 14 07 00 48 FF C8 48 89 3D E8 14 07 00 }
        $code_032_7 = { 55 89 E5 57 53 56 83 E4 F8 81 EC B0 00 00 00 8B }
        $code_032_8 = { 45 08 C7 84 24 B4 00 00 00 00 00 00 00 C7 84 24 }
        $code_048_5 = { 55 89 E5 57 53 56 83 E4 F8 81 EC A0 00 00 00 8B }
        $code_048_6 = { 00 00 66 89 D6 66 89 B4 24 C2 00 00 00 C7 84 24 }
        $code_048_8 = { 00 0A CB E4 55 89 E0 8D 8C 24 C0 00 00 00 89 08 }
        $code_064_2 = { 25 93 14 07 00 48 89 C1 4C 89 05 91 14 07 00 4C }
        $code_064_6 = { 3B 1B 78 60 C7 84 24 84 00 00 00 00 00 00 00 C7 }
        $code_064_7 = { 4F 1F 7A 8A 8C 24 CB 00 00 00 88 CA 80 C2 7A 88 }
        $code_064_9 = { 15 EC 5E 05 10 52 FF 15 74 66 05 10 A1 F4 5E 05 }
        $code_080_3 = { 30 DA 3C C7 84 24 94 00 00 00 00 00 00 00 C7 84 }
        $code_080_4 = { E7 8D 5C 24 28 89 1F 89 44 24 24 66 89 4C 24 22 }
        $code_080_6 = { 24 E4 00 00 00 89 D7 F7 D7 89 F3 F7 D3 89 9C 24 }
        $code_096_9 = { F0 5E 05 10 51 FF 15 80 66 05 10 0F B7 15 E8 5E }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_2 at (pe.entry_point + 0) and $code_032_3 at (pe.entry_point + 32) and $code_064_2 at (pe.entry_point + 64))
                or ($ep_5 at (pe.entry_point + 0) and $code_048_5 at (pe.entry_point + 48) and $code_080_3 at (pe.entry_point + 80))
                or ($code_016_6 at (pe.entry_point + 16) and $code_048_6 at (pe.entry_point + 48) and $code_080_4 at (pe.entry_point + 80))
                or ($code_016_8 at (pe.entry_point + 16) and $code_048_8 at (pe.entry_point + 48) and $code_080_6 at (pe.entry_point + 80))
                or ($ep_9 at (pe.entry_point + 0) and $code_032_7 at (pe.entry_point + 32) and $code_064_6 at (pe.entry_point + 64))
                or ($ep_10 at (pe.entry_point + 0) and $code_032_8 at (pe.entry_point + 32) and $code_064_7 at (pe.entry_point + 64))
                or ($ep_12 at (pe.entry_point + 0) and $code_064_9 at (pe.entry_point + 64) and $code_096_9 at (pe.entry_point + 96))))
}

rule Trojan_WinPE_Emotet
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Emotet"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 6A FF 68 58 5E 40 00 68 3C 3F 40 00 64 }
        $ep_2 = { 6A 60 68 28 B4 40 00 E8 65 15 00 00 BF 94 00 00 }
        $ep_4 = { 6A 60 68 B8 F0 44 00 E8 E2 0F 00 00 BF 94 00 00 }
        $ep_5 = { 55 8B EC 6A FF 68 18 50 40 00 68 8E 39 40 00 64 }
        $ep_8 = { 83 7C 24 08 01 75 05 E8 CE 8E 00 00 FF 74 24 04 }
        $ep_9 = { 55 8B EC 6A FF 68 60 37 40 00 68 74 2A 40 00 64 }
        $ep_10 = { E8 62 49 00 00 E9 79 FE FF FF 3B 0D 70 1C 43 00 }
        $ep_11 = { 55 8B EC 6A FF 68 90 55 40 00 68 C6 4D 40 00 64 }
        $ep_13 = { E8 31 B7 00 00 E9 16 FE FF FF 50 64 FF 35 00 00 }
        $ep_14 = { 55 8B EC 6A FF 68 E8 98 40 00 68 7A 83 40 00 64 }
        $ep_15 = { 83 7C 24 08 01 75 05 E8 59 C7 00 00 FF 74 24 04 }
        $ep_16 = { 55 8B EC 83 7D 0C 01 75 05 E8 0B 46 00 00 FF 75 }
        $ep_21 = { E8 34 9D 00 00 E9 78 FE FF FF 6A 0C 68 C8 F4 42 }
        $ep_33 = { E8 EB 25 01 00 E9 78 FE FF FF 6A 0C 68 A0 1A 4B }
        $ep_35 = { 6A 60 68 D0 01 44 00 E8 9E 0D 00 00 BF 94 00 00 }
        $ep_52 = { E8 94 93 00 00 E9 78 FE FF FF 6A 0C 68 80 5C 42 }
        $ep_61 = { 6A 60 68 88 F6 44 00 E8 E6 12 00 00 BF 94 00 00 }
        $code_032_1 = { C2 0C 00 6A 0C 68 10 4B 05 10 E8 32 26 00 00 33 }
        $code_032_4 = { 53 56 57 89 65 E8 FF 15 F0 E1 41 00 33 D2 8A D4 }
        $code_032_7 = { C2 0C 00 6A 0C 68 78 20 02 10 E8 03 1F 00 00 33 }
        $code_048_7 = { 32 40 00 59 83 0D 44 42 40 00 FF 83 0D 48 42 40 }
        $code_048_8 = { 51 40 00 59 83 0D FC 62 40 00 FF 83 0D 00 63 40 }
        $code_048_11 = { CA 40 00 59 83 0D 8C B5 40 00 FF 83 0D 90 B5 40 }
        $code_064_1 = { 8B 76 0C 81 E6 FF 7F 00 00 89 35 78 DC 40 00 83 }
        $code_064_2 = { 8B 76 0C 81 E6 FF 7F 00 00 89 35 34 E5 45 00 83 }
        $code_080_6 = { FF 15 04 32 40 00 8B 0D 34 42 40 00 89 08 A1 00 }
        $code_080_7 = { 45 08 83 C1 09 51 83 C0 09 50 E8 18 4B 00 00 F7 }
        $code_080_8 = { FF 15 E0 51 40 00 8B 0D EC 62 40 00 89 08 A1 DC }
        $code_080_11 = { FF 15 1C CA 40 00 8B 0D 7C B5 40 00 89 08 A1 18 }
        $code_080_13 = { 02 75 35 8B 0D AC C3 01 10 85 C9 74 0C FF 75 10 }
        $code_096_3 = { C0 75 08 6A 1C E8 C3 00 00 00 59 E8 90 18 00 00 }
        $code_096_5 = { 64 8B 35 00 00 00 00 89 75 FC C7 45 F8 25 F6 01 }
        $code_096_11 = { 2B 64 24 0C 53 56 57 89 28 8B E8 A1 04 A8 0E 10 }
        $code_112_2 = { 83 44 00 FF D7 66 81 38 4D 5A 75 1F 8B 48 3C 03 }
        $code_128_1 = { 40 00 59 E8 FA 00 00 00 68 1C 70 40 00 68 18 70 }
        $code_128_4 = { C1 00 59 E8 FA 00 00 00 68 18 D4 40 00 68 14 D3 }
        $code_160_13 = { 8D 44 24 0C 2B 64 24 0C 53 56 57 89 28 50 5D A1 }
        $code_176_1 = { 75 08 E8 D7 FD FF FF A1 B0 61 04 10 85 C0 74 07 }
        $code_176_2 = { 50 8D 45 A0 50 FF 15 30 53 40 00 68 14 70 40 00 }
        $code_176_4 = { 50 8D 45 A0 50 FF 15 20 43 40 00 68 14 70 40 00 }
        $code_176_9 = { 00 EB 0E 83 79 74 0E 76 E2 29 C0 39 B1 E8 00 00 }
        $code_192_5 = { 68 00 D0 40 00 E8 B2 00 00 00 83 C4 24 A1 54 E5 }
        $code_240_4 = { 5B 8B E5 5D 51 C3 8B 4D F0 33 CD E8 1A D0 FF FF }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_1 at (pe.entry_point + 32) and $code_176_1 at (pe.entry_point + 176))
                or ($ep_1 at (pe.entry_point + 0) and $code_128_1 at (pe.entry_point + 128) and $code_176_2 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or ($ep_5 at (pe.entry_point + 0) and $code_128_1 at (pe.entry_point + 128) and $code_176_4 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_4 at (pe.entry_point + 32) and $code_096_3 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_128_4 at (pe.entry_point + 128) and $code_192_5 at (pe.entry_point + 192))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_8 at (pe.entry_point + 0) and $code_096_5 at (pe.entry_point + 96))
                or ($ep_9 at (pe.entry_point + 0) and $code_048_7 at (pe.entry_point + 48) and $code_080_6 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_10 at (pe.entry_point + 0) and $code_080_7 at (pe.entry_point + 80))
                or ($ep_11 at (pe.entry_point + 0) and $code_048_8 at (pe.entry_point + 48) and $code_080_8 at (pe.entry_point + 80))
                or ($ep_14 at (pe.entry_point + 0) and $code_048_11 at (pe.entry_point + 48) and $code_080_11 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_13 at (pe.entry_point + 0) and $code_240_4 at (pe.entry_point + 240))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_15 at (pe.entry_point + 0) and $code_096_11 at (pe.entry_point + 96))
                or ($ep_16 at (pe.entry_point + 0) and $code_032_7 at (pe.entry_point + 32) and $code_080_13 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_21 at (pe.entry_point + 0) and $code_160_13 at (pe.entry_point + 160))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_33 at (pe.entry_point + 0) and $code_160_13 at (pe.entry_point + 160))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_61 at (pe.entry_point + 0) and $code_112_2 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_52 at (pe.entry_point + 0) and $code_160_13 at (pe.entry_point + 160))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_35 at (pe.entry_point + 0) and $code_176_9 at (pe.entry_point + 176))))
}

rule Trojan_WinPE_Fake
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Fake"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 68 80 12 40 00 E8 EE FF FF FF 00 00 48 00 00 00 }
        $ep_2 = { 68 D0 12 40 00 E8 EE FF FF FF 00 00 68 00 00 00 }
        $ep_3 = { 55 8B EC 6A FF 68 08 81 40 00 68 C4 41 40 00 64 }
        $code_032_1 = { 03 D3 75 4C AE 86 14 37 9E 24 93 F4 00 00 00 00 }
        $code_064_1 = { 6E 6E 69 00 52 65 62 72 6F 61 64 63 61 73 74 20 }
        $code_096_1 = { 02 00 00 00 02 00 00 00 2A F9 AF DF 12 ED A8 48 }
        $code_096_2 = { 72 6F 73 63 6F 70 69 63 61 6C 00 00 00 00 00 00 }
        $code_096_3 = { C0 75 08 6A 1C E8 C3 00 00 00 59 E8 42 23 00 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_096_1 at (pe.entry_point + 96))
                or ($ep_2 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64) and $code_096_2 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_096_3 at (pe.entry_point + 96))))
}

rule Trojan_WinPE_Flooder
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Flooder"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_3 = { 48 83 EC 28 48 8B 05 F5 E4 00 00 C7 00 00 00 00 }
        $code_096_1 = { 53 48 83 EC 30 48 8B 1D 04 E5 00 00 4C 89 4C 24 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_096_1 at (pe.entry_point + 96))))
}

rule Trojan_WinPE_General
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_General"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 8B FF 55 8B EC E8 86 61 00 00 E8 11 00 00 00 5D }
        $ep_2 = { 48 83 EC 28 48 8B 05 15 10 01 00 C7 00 01 00 00 }
        $ep_3 = { E8 68 3B 00 00 E9 89 FE FF FF CC CC CC CC CC CC }
        $ep_4 = { E8 AF 21 00 00 E9 78 FE FF FF 8B FF 55 8B EC 57 }
        $ep_5 = { 8B FF 55 8B EC E8 E6 78 00 00 E8 11 00 00 00 5D }
        $ep_6 = { 8B FF 55 8B EC E8 F6 3B 00 00 E8 11 00 00 00 5D }
        $ep_7 = { E8 32 95 00 00 E9 79 FE FF FF 8B FF 55 8B EC 81 }
        $ep_8 = { 8B FF 56 57 33 F6 E8 5A FF FF FF 8B F8 85 FF 78 }
        $ep_9 = { 8B FF 55 8B EC E8 C6 88 00 00 E8 11 00 00 00 5D }
        $ep_11 = { 8B FF 55 8B EC E8 26 50 00 00 E8 11 00 00 00 5D }
        $ep_14 = { 8B FF 55 8B EC E8 36 57 00 00 E8 11 00 00 00 5D }
        $ep_22 = { E8 E8 63 00 00 E9 78 FE FF FF 8B FF 55 8B EC 8B }
        $code_016_2 = { EC 28 03 00 00 A3 58 17 48 00 89 0D 54 17 48 00 }
        $code_048_5 = { 00 64 A1 00 00 00 00 50 83 C4 94 53 56 57 A1 08 }
        $code_048_6 = { 00 64 A1 00 00 00 00 50 83 C4 98 53 56 57 A1 CC }
        $code_064_1 = { 54 45 00 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 }
        $code_064_2 = { 0D 2B 7A 03 00 74 12 48 3B C8 74 14 33 C0 F0 48 }
        $code_064_4 = { 04 D9 EB DE E1 0A ED 74 02 D9 E0 C3 D9 E1 D9 C0 }
        $code_064_8 = { A6 49 00 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 }
        $code_080_2 = { 00 FF 15 38 10 44 00 33 C0 C3 57 5F 55 8B EC 57 }
        $code_080_5 = { 3C 17 48 00 66 8C 25 38 17 48 00 66 8C 2D 34 17 }
        $code_080_6 = { 41 54 56 53 65 48 8B 04 25 60 00 00 00 48 8B 40 }
        $code_096_5 = { FA 03 C2 89 7D B4 89 45 A8 8B F3 89 75 C4 8B 08 }
        $code_112_5 = { 00 6A 00 6A 01 6A 00 FF 15 88 40 42 00 E8 8E 01 }
        $code_112_6 = { EB 7E 66 0F 1F 44 00 00 4D 8B 00 4D 39 C3 74 70 }
        $code_112_8 = { 00 6A 00 6A 01 6A 00 FF 15 4C 31 42 00 E8 8E 01 }
        $code_128_1 = { 7C 05 00 00 E8 B7 0C 00 00 84 C0 74 10 E8 CA E0 }
        $code_128_2 = { 94 C5 74 05 48 39 C6 75 E7 4C 8B 35 C0 0F 01 00 }
        $code_128_5 = { 00 00 89 45 94 E8 76 75 00 00 85 C0 75 0A 6A 1C }
        $code_144_10 = { C0 74 E5 66 D1 E8 74 E0 83 E8 01 4D 8B 60 20 B9 }
        $code_160_1 = { 00 89 45 94 6A 01 E8 B5 81 00 00 83 C4 04 85 C0 }
        $code_160_4 = { 00 89 45 94 6A 01 E8 55 90 00 00 83 C4 04 85 C0 }
        $code_176_4 = { 0C 5D C3 90 90 55 8B EC 68 80 11 44 00 FF 15 3C }
        $code_176_7 = { 08 E8 36 22 00 00 59 C3 8B FF 55 8B EC 56 8B F0 }
        $code_176_11 = { 75 0A 6A 1C E8 47 01 00 00 83 C4 04 E8 8F 7D 00 }
        $code_208_4 = { 10 44 00 09 C0 74 05 FF 75 08 FF D0 5D C3 90 90 }
        $code_224_8 = { 8C 91 00 00 A3 9C EF 49 00 E8 92 8D 00 00 85 C0 }
        $code_224_10 = { C0 75 10 48 8D 0D DE 7B 03 00 E8 A9 DE 00 00 85 }
        $code_240_8 = { 00 00 75 08 6A 01 E8 D2 94 00 00 59 68 09 04 00 }
        $code_240_12 = { C7 02 00 00 6A 04 E8 B9 1E 00 00 6A 02 BF 80 01 }
        $code_240_13 = { 7D 0A 6A 08 E8 A7 02 00 00 83 C4 04 E8 4F 5A 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_160_1 at (pe.entry_point + 160))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_064_2 at (pe.entry_point + 64) and $code_128_1 at (pe.entry_point + 128))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_128_2 at (pe.entry_point + 128))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_4 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_5 at (pe.entry_point + 0) and $code_160_4 at (pe.entry_point + 160))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_176_7 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_2 at (pe.entry_point + 16) and $code_080_5 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_6 at (pe.entry_point + 0) and $code_128_5 at (pe.entry_point + 128))
                or (pe.imports("api-ms-win-core-memory-l1-1-0.dll", "VirtualProtect") and pe.imports("api-ms-win-core-libraryloader-l1-2-0.dll", "GetProcAddress") and $ep_8 at (pe.entry_point + 0) and $code_096_5 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_048_5 at (pe.entry_point + 48) and $code_176_11 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_9 at (pe.entry_point + 0) and $code_112_8 at (pe.entry_point + 112))
                or ($code_080_6 at (pe.entry_point + 80) and $code_112_6 at (pe.entry_point + 112) and $code_144_10 at (pe.entry_point + 144))
                or ($ep_11 at (pe.entry_point + 0) and $code_048_6 at (pe.entry_point + 48) and $code_112_5 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_064_8 at (pe.entry_point + 64) and $code_224_8 at (pe.entry_point + 224))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_14 at (pe.entry_point + 0) and $code_240_13 at (pe.entry_point + 240))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_128_1 at (pe.entry_point + 128) and $code_224_10 at (pe.entry_point + 224))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_22 at (pe.entry_point + 0) and $code_240_12 at (pe.entry_point + 240))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_7 at (pe.entry_point + 0) and $code_240_8 at (pe.entry_point + 240))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_080_2 at (pe.entry_point + 80) and $code_208_4 at (pe.entry_point + 208))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_080_2 at (pe.entry_point + 80) and $code_176_4 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Trojan_WinPE_Hijack
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Hijack"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 98 43 00 00 }
        $ep_2 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 01 63 00 00 }
        $code_048_2 = { 33 C0 8A 44 24 08 84 C0 75 16 81 FA 80 00 00 00 }
        $code_096_1 = { 75 E4 FF 75 E0 FF 15 64 81 01 10 C9 C2 08 00 CC }
        $code_144_2 = { 01 75 F6 8B 44 24 08 5F C3 8B 44 24 04 C3 8B FF }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_2 at (pe.entry_point + 0) and $code_048_2 at (pe.entry_point + 48) and $code_144_2 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_096_1 at (pe.entry_point + 96))))
}

rule Trojan_WinPE_Injector
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Injector"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_3 = { 60 BE 00 00 43 00 8D BE 00 10 FD FF 57 EB 0B 90 }
        $ep_4 = { 81 EC 7C 01 00 00 53 55 56 33 F6 57 89 74 24 18 }
        $ep_5 = { 55 8B EC 83 C4 F0 B8 80 A4 48 00 E8 2C B8 F7 FF }
        $ep_7 = { E8 04 04 00 00 E9 74 FE FF FF 55 8B EC 83 EC 0C }
        $ep_9 = { 55 8B EC 83 C4 F0 B8 1C B3 46 00 E8 78 AA F9 FF }
        $ep_10 = { 55 8B EC 83 C4 F0 B8 18 47 46 00 E8 74 1D FA FF }
        $code_016_1 = { C7 44 24 10 58 91 40 00 33 F6 C6 44 24 14 20 FF }
        $code_016_2 = { 89 45 20 48 8B 05 E4 4F 02 00 C7 00 00 00 00 00 }
        $code_032_5 = { 50 E8 82 09 00 00 CC 55 8B EC 83 EC 0C 8D 4D F4 }
        $code_032_8 = { DB 72 ED 9C 31 C0 40 9D 01 DB 75 07 8B 1E 83 EE }
        $code_048_2 = { C2 40 00 59 83 0D AC 0F 44 00 FF 83 0D B0 0F 44 }
        $code_064_4 = { 09 00 00 CC E9 1E 5A 00 00 55 8B EC 6A 00 FF 15 }
        $code_080_1 = { 00 00 50 53 68 90 8F 42 00 FF 15 58 71 40 00 68 }
        $code_080_3 = { 45 FC 01 00 00 00 48 8B 05 C1 4F 02 00 8B 55 18 }
        $code_096_3 = { 70 40 00 E8 64 FF FF FF 85 C0 75 24 68 FB 03 00 }
        $code_096_6 = { C9 EB 52 29 C9 83 E8 03 72 11 C1 E0 08 8A 06 46 }
        $code_112_2 = { 1D C0 0E 44 00 75 0C 68 92 B2 40 00 FF 15 AC C2 }
        $code_112_3 = { 30 00 00 6A 08 E8 DB 30 00 00 6A 06 A3 24 F4 42 }
        $code_112_6 = { 83 F0 FF 74 75 D1 F8 50 5D EB 0B 01 DB 75 07 8B }
        $code_112_8 = { 00 A3 A4 27 7A 00 FF 15 38 70 40 00 53 FF 15 6C }
        $code_128_3 = { 00 00 00 00 28 21 40 00 B8 22 40 00 38 26 40 00 }
        $code_144_2 = { 74 07 80 0D 2F F4 42 00 40 55 FF 15 40 80 40 00 }
        $code_144_5 = { 00 00 50 53 68 58 DD 79 00 FF 15 5C 71 40 00 68 }
        $code_176_2 = { 38 68 60 01 00 00 50 53 68 58 98 42 00 FF 15 78 }
        $code_176_5 = { 08 71 40 00 BD 00 80 7A 00 50 55 E8 F5 29 00 00 }
        $code_224_4 = { 04 77 F1 01 CF E9 2C FF FF FF 5E 56 5F B9 D3 02 }
        $code_224_6 = { 00 00 00 00 32 13 8B C0 02 00 8B C0 00 8D 40 00 }
        $code_224_7 = { 02 8D 40 00 32 13 8B C0 02 00 8B C0 00 8D 40 00 }
    condition:
        (General_WinPE_AnySizePE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_048_2 at (pe.entry_point + 48) and $code_112_2 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_2 at (pe.entry_point + 16) and $code_080_3 at (pe.entry_point + 80))
                or ($code_112_3 at (pe.entry_point + 112) and $code_144_2 at (pe.entry_point + 144) and $code_176_2 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_096_3 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_5 at (pe.entry_point + 0) and $code_128_3 at (pe.entry_point + 128))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_224_4 at (pe.entry_point + 224))
                or ($ep_7 at (pe.entry_point + 0) and $code_032_5 at (pe.entry_point + 32) and $code_064_4 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_9 at (pe.entry_point + 0) and $code_224_6 at (pe.entry_point + 224))
                or ($code_112_8 at (pe.entry_point + 112) and $code_144_5 at (pe.entry_point + 144) and $code_176_5 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_10 at (pe.entry_point + 0) and $code_224_7 at (pe.entry_point + 224))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_112_6 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_8 at (pe.entry_point + 32) and $code_096_6 at (pe.entry_point + 96))))
}

rule Trojan_WinPE_KillDisk
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_KillDisk"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 55 8B EC 83 E4 F8 81 EC 24 05 00 00 53 56 57 6A }
        $code_064_1 = { C7 44 24 20 00 00 00 00 33 F6 FF 15 EC 50 40 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("advapi32.dll", "OpenSCManagerW") and pe.imports("advapi32.dll", "CreateServiceW") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Trojan_WinPE_Loader
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Loader"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_3 = { 40 53 48 83 EC 30 E8 65 DB FF FF 85 C0 0F 84 93 }
        $ep_5 = { 40 53 48 81 EC 80 00 00 00 33 DB 48 8D 4C 24 48 }
        $code_032_1 = { C2 0C 00 CC CC CC CC CC 6A 10 68 88 92 96 12 E8 }
        $code_048_5 = { 83 65 F8 00 50 FF 15 74 51 29 10 8B 45 F8 33 45 }
        $code_064_2 = { 84 C0 74 6B E8 3B FF FF FF 85 C0 74 59 48 83 64 }
        $code_064_3 = { 48 0F B1 0D 5C E0 00 00 75 EE 32 C0 48 83 C4 28 }
        $code_064_6 = { 07 00 00 E8 88 83 00 00 B8 01 00 00 00 48 81 C4 }
        $code_080_2 = { 8B F9 75 5E 25 F0 3F FF 0F 48 C7 05 D0 A2 01 00 }
        $code_080_5 = { 50 29 10 31 45 FC 8D 45 EC 50 FF 15 70 52 29 10 }
        $code_096_1 = { 05 83 FF 02 75 38 A1 E4 4C 5C 12 85 C0 74 0E FF }
        $code_112_3 = { 8B 0D 04 A0 3F 10 56 57 BF 4E E6 40 BB BE 00 00 }
        $code_144_2 = { 28 C3 CC CC 40 53 48 83 EC 20 80 3D 0C E0 00 00 }
        $code_160_3 = { 05 9F AD 01 00 41 83 C8 01 44 89 05 94 AD 01 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_1 at (pe.entry_point + 32) and $code_096_1 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_064_3 at (pe.entry_point + 64) and $code_144_2 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_080_2 at (pe.entry_point + 80) and $code_160_3 at (pe.entry_point + 160))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_5 at (pe.entry_point + 0) and $code_064_6 at (pe.entry_point + 64))
                or ($code_048_5 at (pe.entry_point + 48) and $code_080_5 at (pe.entry_point + 80) and $code_112_3 at (pe.entry_point + 112))))
}

rule Trojan_WinPE_MalBehav
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_MalBehav"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { F9 72 07 1F 33 71 B7 98 C9 EB 60 EB 03 3A 95 D2 }
        $ep_3 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 }
        $ep_4 = { 60 BE 15 F0 40 00 8D BE EB 1F FF FF 57 83 CD FF }
        $ep_5 = { 60 BE 15 00 41 00 8D BE EB 0F FF FF 57 83 CD FF }
        $ep_6 = { 60 BE 00 20 67 00 8D BE 00 F0 D8 FF C7 87 C4 E8 }
        $ep_7 = { 48 83 EC 28 E8 CF 44 00 00 48 83 C4 28 E9 72 FE }
        $ep_8 = { 68 85 90 40 00 E8 01 00 00 00 C3 C3 60 8B 74 24 }
        $ep_9 = { 60 BE 00 80 4C 00 8D BE 00 90 F3 FF 57 83 CD FF }
        $ep_10 = { 60 BE 15 10 41 00 8D BE EB FF FE FF 57 83 CD FF }
        $code_064_1 = { CF 2A 4A 0F 84 80 00 00 00 EB 07 9E 7E E0 68 BC }
        $code_064_2 = { FF FF 75 02 F3 C3 48 C1 C9 10 E9 91 4A 00 00 CC }
        $code_064_3 = { 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB }
        $code_064_4 = { 3B AD 8B C8 0F BA F7 1F 73 07 F3 A5 E9 88 00 00 }
        $code_064_5 = { 03 3B 60 50 57 56 FF 53 14 89 44 24 18 61 60 2B }
        $code_208_2 = { FF FF 5E 89 F7 B9 B3 02 00 00 8A 07 47 2C E8 3C }
        $code_240_3 = { 04 77 F1 01 CF E9 2C FF FF FF 5E 89 F7 B9 D7 50 }
        $code_240_4 = { FF FF 5E 89 F7 B9 66 08 00 00 8A 07 47 2C E8 3C }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_208_2 at (pe.entry_point + 208))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_6 at (pe.entry_point + 0) and $code_240_3 at (pe.entry_point + 240))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_7 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_5 at (pe.entry_point + 0) and $code_208_2 at (pe.entry_point + 208))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_9 at (pe.entry_point + 0) and $code_240_4 at (pe.entry_point + 240))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_8 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_5 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_4 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_10 at (pe.entry_point + 0) and $code_208_2 at (pe.entry_point + 208))))
}

rule Trojan_WinPE_Maloader
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Maloader"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $code_016_1 = { F6 75 09 83 3D 08 31 00 10 00 EB 26 83 FE 01 74 }
        $code_064_1 = { 85 C0 75 04 33 C0 EB 4E 57 56 53 E8 E5 00 00 00 }
        $code_096_1 = { 5E 5D C3 8B C2 EB F9 E8 53 07 00 00 85 C0 75 03 }
        $code_112_1 = { 8B 0D 24 40 01 10 56 57 BF 4E E6 40 BB BE 00 00 }
        $code_128_1 = { 74 11 A1 18 31 00 10 85 C0 74 08 57 56 53 FF D0 }
        $code_144_1 = { 85 C0 75 F0 32 C0 5E C3 B0 01 5E C3 E8 1E 07 00 }
        $code_160_2 = { 0D 11 47 00 00 C1 E0 10 0B C8 89 0D 24 40 01 10 }
        $code_176_2 = { 5F C2 10 00 CC CC CC CC CC CC 51 8D 4C 24 04 2B }
        $code_176_4 = { 00 50 E8 5B 1B 00 00 59 85 C0 74 03 32 C0 C3 E8 }
        $code_208_2 = { 00 59 C3 B8 D8 48 01 10 C3 B8 E0 48 01 10 C3 E8 }
        $code_240_1 = { 06 7C 15 C5 FA 7E C0 62 F1 FD 08 7A C0 C5 F9 7E }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_016_1 at (pe.entry_point + 16) and $code_064_1 at (pe.entry_point + 64) and $code_128_1 at (pe.entry_point + 128))
                or ($code_112_1 at (pe.entry_point + 112) and $code_160_2 at (pe.entry_point + 160) and $code_208_2 at (pe.entry_point + 208))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_176_2 at (pe.entry_point + 176) and $code_240_1 at (pe.entry_point + 240))
                or ($code_096_1 at (pe.entry_point + 96) and $code_144_1 at (pe.entry_point + 144) and $code_176_4 at (pe.entry_point + 176))))
}

rule Trojan_WinPE_Miniduke
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Miniduke"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { E8 3F 2A 00 00 E9 89 FE FF FF CC CC CC CC CC CC }
        $code_064_1 = { F3 4A 00 00 74 13 57 56 83 E7 0F 83 E6 0F 3B FE }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Trojan_WinPE_Obfuscated
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Obfuscated"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { E8 00 60 00 00 73 EB EB EB EB 73 23 7D AB EB F3 }
        $ep_3 = { 8D 35 20 10 40 00 8D 1D B4 3F 40 00 8B 13 31 16 }
        $ep_4 = { 6A 60 68 78 B0 41 00 E8 C2 13 00 00 BF 94 00 00 }
        $ep_6 = { 8B FF 55 8B EC E8 56 AA 00 00 E8 11 00 00 00 5D }
        $code_032_1 = { EB 0E 27 7D AB EB 73 EB EB EB EB 73 EB 1B EB EB }
        $code_048_5 = { 00 64 A1 00 00 00 00 50 83 C4 98 53 56 57 A1 A8 }
        $code_064_1 = { 07 AC EB EB F3 97 85 EB EB F3 07 80 EB EB F3 E4 }
        $code_064_3 = { 8B 76 0C 81 E6 FF 7F 00 00 89 35 78 38 42 00 83 }
        $code_112_2 = { 00 00 00 00 68 01 47 6C 6F 62 61 6C 41 6C 6C 6F }
        $code_112_3 = { 00 6A 00 6A 01 6A 00 FF 15 EC 11 40 00 E8 8E 01 }
        $code_144_3 = { 00 00 B6 00 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))
                or ($ep_3 at (pe.entry_point + 0) and $code_112_2 at (pe.entry_point + 112) and $code_144_3 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))
                or ($ep_6 at (pe.entry_point + 0) and $code_048_5 at (pe.entry_point + 48) and $code_112_3 at (pe.entry_point + 112))))
}

rule Trojan_WinPE_Pikabot
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Pikabot"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { E8 3D 0C 00 00 E9 78 FE FF FF 8B 4D F4 64 89 0D }
        $code_048_1 = { 55 8B EC 83 EC 18 C6 45 E8 44 C6 45 E9 6C C6 45 }
        $code_064_1 = { 89 28 8B E8 A1 64 91 4D 00 33 C5 50 FF 75 FC C7 }
        $code_112_2 = { F6 76 C6 45 F7 65 C6 45 F8 72 C6 45 F9 00 8D 45 }
        $code_144_1 = { 08 89 45 FC FF 55 FC 33 C0 8B E5 5D C3 CC CC CC }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or ($code_048_1 at (pe.entry_point + 48) and $code_112_2 at (pe.entry_point + 112) and $code_144_1 at (pe.entry_point + 144))))
}

rule Trojan_WinPE_Ramnit
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Ramnit"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 81 C4 F4 FE FF FF 83 7D 0C 01 75 59 68 }
        $code_032_1 = { 68 04 01 00 00 8D 85 F4 FE FF FF 50 FF 75 08 E8 }
        $code_064_1 = { 8B F8 68 13 30 00 10 57 E8 59 00 00 00 8D 85 F4 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule Trojan_WinPE_Sefnit
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Sefnit"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 DE 15 00 00 }
        $code_016_1 = { 10 B0 76 88 44 24 06 88 44 24 0E 8B 44 24 18 C6 }
        $code_080_1 = { 0B 35 C6 44 24 0C 33 C6 44 24 0D F5 C6 44 24 0F }
        $code_128_1 = { 71 06 33 D2 57 8D 44 08 18 85 F6 74 1B 8B 7D 0C }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_128_1 at (pe.entry_point + 128))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80))))
}

rule Trojan_WinPE_ShellLoader
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_ShellLoader"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_2 = { 55 8B EC 83 C4 F0 B8 18 96 AB 00 E8 18 88 94 FF }
        $ep_4 = { 48 83 EC 28 E8 27 24 00 00 48 83 C4 28 E9 56 FE }
        $code_032_3 = { 48 89 CE 89 D3 41 89 14 24 4C 89 C7 75 42 8B 05 }
        $code_032_4 = { 05 83 FE 02 75 22 A1 54 FA 43 00 85 C0 74 09 57 }
        $code_064_1 = { 48 83 EC 48 48 8D 4C 24 20 E8 02 DA FF FF 48 8D }
        $code_064_3 = { FF 25 50 B0 AD 00 33 C0 5A 59 59 64 89 10 68 57 }
        $code_064_5 = { 60 48 8B 4C 24 58 E8 25 66 01 00 48 89 44 24 50 }
        $code_096_1 = { 40 53 48 83 EC 20 48 8B D9 33 C9 FF 15 53 40 02 }
        $code_128_1 = { 74 11 A1 54 FA 43 00 85 C0 74 08 57 56 53 FF D0 }
        $code_144_1 = { 38 40 02 00 48 89 4C 24 08 48 83 EC 38 B9 17 00 }
        $code_144_3 = { 01 89 C5 75 BD 85 C0 75 B9 49 89 F8 31 D2 48 89 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_064_1 at (pe.entry_point + 64) and $code_096_1 at (pe.entry_point + 96) and $code_144_1 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_4 at (pe.entry_point + 32) and $code_128_1 at (pe.entry_point + 128))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_3 at (pe.entry_point + 32) and $code_144_3 at (pe.entry_point + 144))
                or (pe.imports("kernel32", "LoadLibraryA") and pe.imports("kernel32", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_064_5 at (pe.entry_point + 64))))
}

rule Trojan_WinPE_Small
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_Small"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 68 EE 41 40 00 6A 00 FF 35 34 55 40 00 E8 B2 0C }
        $code_064_1 = { 83 3D 2C 55 40 00 00 76 1F 6A 05 6A 00 6A 00 68 }
        $code_096_1 = { 6A 00 E8 39 0C 00 00 C3 83 3D 30 55 40 00 00 76 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64) and $code_096_1 at (pe.entry_point + 96))))
}

rule Trojan_WinPE_StartPage
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_StartPage"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_032_1 = { 53 56 57 89 65 E8 FF 15 DC F1 41 00 33 D2 8A D4 }
        $code_032_2 = { DB 89 5D E0 88 5D E7 89 5D FC 3B 5D 10 74 1A 8B }
        $code_096_1 = { C0 75 08 6A 1C E8 AB 00 00 00 59 E8 9A 32 00 00 }
        $code_096_2 = { 14 00 8B 5D E0 8A 45 E7 84 C0 75 0F FF 75 18 53 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_1 at (pe.entry_point + 32) and $code_096_1 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_2 at (pe.entry_point + 32) and $code_096_2 at (pe.entry_point + 96))))
}

rule Trojan_WinPE_TrickBot
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_TrickBot"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 6A FF 68 00 38 46 00 68 14 62 40 00 64 }
        $ep_2 = { E8 C6 F5 00 00 E9 78 FE FF FF 6A 0C 68 98 04 4C }
        $ep_4 = { 83 EC 1C C7 04 24 02 00 00 00 FF 15 1C 53 44 00 }
        $code_032_1 = { FF 15 84 92 42 00 8B 4E 10 89 0D F4 80 43 00 8B }
        $code_048_1 = { 70 40 00 59 83 0D 38 88 46 00 FF 83 0D 3C 88 46 }
        $code_064_3 = { FF FF E8 09 00 00 00 8B 45 E4 E8 B6 04 00 00 C3 }
        $code_080_1 = { FF 15 A0 70 40 00 8B 0D 30 88 46 00 89 08 A1 78 }
        $code_080_4 = { 01 00 52 85 C0 74 65 C7 44 24 04 13 40 42 00 89 }
        $code_112_1 = { 92 42 00 FF D7 66 81 38 4D 5A 75 1F 8B 48 3C 03 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_1 at (pe.entry_point + 32) and $code_112_1 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_4 at (pe.entry_point + 0) and $code_080_4 at (pe.entry_point + 80))))
}

rule Trojan_WinPE_VBClone
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_VBClone"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 68 0C 50 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 }
        $code_032_1 = { 57 28 EB 4F 92 77 13 42 9B AB 65 21 00 00 00 00 }
        $code_080_1 = { FF CC 31 00 00 B0 AE B3 E5 65 9E B1 42 8B 44 1B }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_080_1 at (pe.entry_point + 80))))
}

rule Trojan_WinPE_VFlooder
{
    meta:
        description = "Shared family entry-point code clusters for Trojan_WinPE_VFlooder"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_2 = { 55 8B EC 81 EC 54 02 00 00 68 08 02 00 00 8D 85 }
        $code_032_2 = { 00 00 00 00 8D 4D F4 51 8D 95 E8 FD FF FF 52 E8 }
        $code_064_1 = { 50 8B 8D E0 FD FF FF 51 8D 95 B0 FD FF FF 52 E8 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_2 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule VirTool_MSIL_Obfuscator
{
    meta:
        description = "Shared family entry-point code clusters for VirTool_MSIL_Obfuscator"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_12 = { FF 25 00 20 40 00 00 FF 55 FF 00 00 00 00 08 00 }
        $ep_22 = { FF 25 00 20 40 00 00 80 0D 00 EF 36 0E 00 00 40 }
        $code_032_4 = { 46 00 47 00 48 00 49 00 4A 00 4B 00 4C 00 4D 00 }
        $code_096_1 = { 6C 00 6D 00 6E 00 6F 00 70 00 71 00 72 00 73 00 }
        $code_176_3 = { 46 00 47 00 48 00 49 00 4A 00 4B 00 4C 00 4D 00 }
        $code_176_7 = { FF FF 2C 07 01 00 69 15 01 00 BB 28 01 00 C3 28 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.data_directories[14].size > 0 and $code_032_4 at (pe.entry_point + 32) and $code_096_1 at (pe.entry_point + 96))
                or (pe.data_directories[14].size > 0 and $ep_12 at (pe.entry_point + 0) and $code_176_3 at (pe.entry_point + 176))
                or (pe.data_directories[14].size > 0 and $ep_22 at (pe.entry_point + 0) and $code_176_7 at (pe.entry_point + 176))))
}

rule VirTool_VB_Obfuscator
{
    meta:
        description = "Shared family entry-point code clusters for VirTool_VB_Obfuscator"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples containing Visual Basic artifacts or payloads; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_8 = { 55 8B EC 6A FF 68 D8 81 40 00 68 AC 56 40 00 64 }
        $code_144_1 = { 15 00 00 E8 F6 01 00 00 89 75 D0 8D 45 A4 50 FF }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_8 at (pe.entry_point + 0) and $code_144_1 at (pe.entry_point + 144))))
}

rule VirTool_Win64_Obfuscator
{
    meta:
        description = "Shared family entry-point code clusters for VirTool_Win64_Obfuscator"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 48 31 3D 11 0E 09 00 4C 31 05 D2 0D 09 00 48 31 }
        $code_016_2 = { 44 24 48 0F 57 C0 66 C7 44 24 23 30 00 44 8B D2 }
        $code_032_2 = { 0D 09 00 4C 31 3D C6 0D 09 00 4C 31 35 C7 0D 09 }
        $code_048_1 = { 44 24 22 32 0F 11 44 24 38 BA 04 00 00 00 33 C0 }
        $code_064_2 = { 31 25 92 0D 09 00 48 8B 05 33 0F 09 00 EB 09 4C }
        $code_080_3 = { 01 75 ED 0F B6 4C 24 28 0F B6 C1 C0 E0 02 02 C8 }
        $code_096_1 = { 85 C0 74 E7 48 83 C4 40 5B C3 8B 05 54 CF 00 00 }
        $code_128_1 = { 75 39 41 0B C0 48 8D 54 24 58 48 8D 0D 1B CF 00 }
        $code_160_1 = { 44 24 58 E8 84 05 00 00 48 8D 0D E5 69 00 00 48 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_096_1 at (pe.entry_point + 96) and $code_128_1 at (pe.entry_point + 128) and $code_160_1 at (pe.entry_point + 160))
                or ($code_016_2 at (pe.entry_point + 16) and $code_048_1 at (pe.entry_point + 48) and $code_080_3 at (pe.entry_point + 80))
                or ($ep_1 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_064_2 at (pe.entry_point + 64))))
}

rule VirTool_WinPE_DelfInjector
{
    meta:
        description = "Shared family entry-point code clusters for VirTool_WinPE_DelfInjector"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_5 = { 55 8B EC 83 C4 F0 B8 E0 88 53 00 E8 E8 DE EC FF }
        $code_224_1 = { 00 00 00 00 48 24 40 00 D8 25 40 00 58 29 40 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_5 at (pe.entry_point + 0) and $code_224_1 at (pe.entry_point + 224))))
}

rule VirTool_WinPE_DelfObfuscator
{
    meta:
        description = "Shared family entry-point code clusters for VirTool_WinPE_DelfObfuscator"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 83 C4 F0 B8 48 33 49 00 E8 D0 25 F7 FF }
        $ep_2 = { 55 8B EC 83 C4 F0 B8 18 B6 47 00 E8 C4 A1 F8 FF }
        $ep_3 = { 55 8B EC 83 C4 F0 B8 A8 28 46 00 E8 64 32 FA FF }
        $code_064_1 = { 28 08 49 00 E8 C3 9F FC FF A1 48 76 49 00 8B 00 }
        $code_064_2 = { F0 98 48 00 8B 00 E8 C5 56 FE FF E8 C8 7E F8 FF }
        $code_064_3 = { 00 8B 15 E8 22 46 00 E8 EC 85 FF FF A1 44 97 48 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))))
}

rule VirTool_WinPE_Emotet
{
    meta:
        description = "Shared family entry-point code clusters for VirTool_WinPE_Emotet"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { E8 1E 8C 00 00 E9 78 FE FF FF 6A 0C 68 00 76 42 }
        $ep_2 = { 55 54 5D 6A FF 68 B0 CF 44 00 68 54 68 41 00 64 }
        $code_064_1 = { 56 50 E8 5F 4A 00 00 59 59 C7 45 FC FE FF FF FF }
        $code_064_2 = { 8C 06 46 00 C1 E1 08 03 CA 89 0D 88 06 46 00 C1 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))))
}

rule VirTool_WinPE_Obfuscator
{
    meta:
        description = "Shared family entry-point code clusters for VirTool_WinPE_Obfuscator"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 55 8B EC 6A FF 68 18 F2 40 00 68 6C 63 40 00 64 }
        $ep_3 = { 8B FF 55 8B EC E8 76 79 00 00 E8 11 00 00 00 5D }
        $ep_4 = { 40 F3 0F C2 CA 03 E8 95 CD FF FF CC CC CC CC CC }
        $ep_5 = { 40 F3 0F C2 CA 03 E8 D5 CD FF FF CC CC CC CC CC }
        $ep_6 = { 55 8B EC 51 C7 45 FC 1C 10 00 00 83 3D F4 13 80 }
        $ep_7 = { 48 89 0D 39 06 07 00 48 8D 0D F2 F2 FF FF 4C 89 }
        $ep_8 = { E8 98 35 00 00 E9 78 FE FF FF CC CC CC CC CC CC }
        $ep_9 = { 8D 05 70 27 40 00 F3 0F C2 CA 03 50 B8 00 00 00 }
        $ep_10 = { 8B FF 55 8B EC E8 D6 74 00 00 E8 11 00 00 00 5D }
        $ep_11 = { 83 7C 24 08 01 75 05 E8 33 50 00 00 FF 74 24 04 }
        $ep_91 = { 8B FF 55 8B EC E8 06 75 00 00 E8 11 00 00 00 5D }
        $code_016_6 = { EC 28 03 00 00 A3 D8 61 40 00 89 0D D4 61 40 00 }
        $code_016_7 = { CC CC CC CC CC 8B 4C 24 04 F7 C1 03 00 00 00 74 }
        $code_032_2 = { 45 08 66 B9 33 DA 0F B7 94 24 A6 00 00 00 66 89 }
        $code_032_3 = { 45 08 8A 8C 24 8B 00 00 00 66 C7 44 24 76 19 A5 }
        $code_032_4 = { 83 3D F4 13 80 00 00 74 05 E8 02 D5 FF FF 68 18 }
        $code_032_5 = { 06 07 00 48 31 C0 48 FF C0 48 01 C1 4C 89 25 55 }
        $code_048_2 = { 00 64 A1 00 00 00 00 50 83 C4 94 53 56 57 A1 E4 }
        $code_048_8 = { 40 00 89 3D C4 61 40 00 66 8C 15 F0 61 40 00 66 }
        $code_064_1 = { 48 33 41 00 C1 E1 08 03 CA 89 0D 44 33 41 00 C1 }
        $code_064_3 = { 61 42 00 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 }
        $code_064_4 = { 00 00 C7 84 24 A0 00 00 00 B6 D5 EF 43 C6 84 24 }
        $code_064_5 = { 54 24 78 8B 75 08 89 E7 89 37 89 44 24 24 88 4C }
        $code_064_6 = { F8 02 74 07 33 C0 E9 8D 12 00 00 6A 00 6A 00 68 }
        $code_064_7 = { 74 3B 48 89 25 0F 06 07 00 48 89 2D 00 06 07 00 }
        $code_064_9 = { 70 42 00 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 }
        $code_080_6 = { BC 61 40 00 66 8C 25 B8 61 40 00 66 8C 2D B4 61 }
        $code_096_8 = { 84 C0 74 32 84 E4 74 24 A9 00 00 FF 00 74 13 A9 }
        $code_096_10 = { E0 FF 15 80 90 01 10 C9 C2 08 00 55 8B EC 51 53 }
        $code_096_11 = { 00 00 8B F0 85 F6 0F 84 45 01 00 00 8B 56 5C 8B }
        $code_112_8 = { 90 CC FF 25 10 90 40 00 FF 25 C0 90 40 00 FF 25 }
        $code_144_8 = { FF 25 EC 90 40 00 FF 25 24 90 40 00 FF 25 DC 90 }
        $code_160_11 = { 08 85 D2 0F 84 05 01 00 00 83 FA 05 75 0C 83 61 }
        $code_176_1 = { 75 0A 6A 1C E8 47 01 00 00 83 C4 04 E8 BF 42 00 }
        $code_208_8 = { 8D 45 F4 50 FF 75 F0 FF 75 E4 FF 75 E0 FF 15 14 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_048_2 at (pe.entry_point + 48) and $code_176_1 at (pe.entry_point + 176))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))
                or ($ep_4 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_064_4 at (pe.entry_point + 64))
                or ($ep_5 at (pe.entry_point + 0) and $code_032_3 at (pe.entry_point + 32) and $code_064_5 at (pe.entry_point + 64))
                or ($ep_6 at (pe.entry_point + 0) and $code_032_4 at (pe.entry_point + 32) and $code_064_6 at (pe.entry_point + 64))
                or ($ep_7 at (pe.entry_point + 0) and $code_032_5 at (pe.entry_point + 32) and $code_064_7 at (pe.entry_point + 64))
                or ($code_016_6 at (pe.entry_point + 16) and $code_048_8 at (pe.entry_point + 48) and $code_080_6 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_8 at (pe.entry_point + 0) and $code_208_8 at (pe.entry_point + 208))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_7 at (pe.entry_point + 16) and $code_096_8 at (pe.entry_point + 96))
                or ($ep_9 at (pe.entry_point + 0) and $code_112_8 at (pe.entry_point + 112) and $code_144_8 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_11 at (pe.entry_point + 0) and $code_096_10 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_096_11 at (pe.entry_point + 96) and $code_160_11 at (pe.entry_point + 160))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_10 at (pe.entry_point + 0) and $code_064_9 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_91 at (pe.entry_point + 0) and $code_064_9 at (pe.entry_point + 64))))
}

rule Virus_Win64_Expiro
{
    meta:
        description = "Shared family entry-point code clusters for Virus_Win64_Expiro"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 47 51 50 45 52 43 B9 60 00 00 00 65 49 8B 01 45 }
        $ep_2 = { 43 54 47 50 51 4F BC 60 00 00 00 00 00 00 00 65 }
        $code_032_1 = { 8B 10 4B 8B 42 10 47 55 4C 8B 48 30 4F 85 C9 74 }
        $code_032_2 = { 49 8B 48 18 4E 8B 41 10 56 4F 8B 60 30 4D 85 E4 }
        $code_032_4 = { 20 48 8B 05 70 3F 1F 00 48 BB 32 A2 DF 2D 99 2B }
        $code_064_1 = { 8B 52 0C 41 C1 E2 08 45 01 EA 45 C1 EA 01 41 81 }
        $code_064_2 = { 00 DF 00 48 8B 49 0B 03 CE C1 E9 02 81 E9 D2 4C }
        $code_096_4 = { 8B C0 48 8D 4D 20 48 31 45 10 FF 15 38 35 1E 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))
                or ($ep_2 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("api-ms-win-service-management-l1-1-0.dll", "OpenSCManagerW") and pe.imports("api-ms-win-service-management-l1-1-0.dll", "CreateServiceW") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_032_4 at (pe.entry_point + 32) and $code_096_4 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Virus_WinPE_Expiro
{
    meta:
        description = "Shared family entry-point code clusters for Virus_WinPE_Expiro"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { E8 4E 05 00 00 E9 39 FE FF FF CC CC CC CC CC CC }
        $ep_2 = { 52 50 53 BA 18 00 00 00 64 8B 02 03 C2 01 D0 8B }
        $code_032_1 = { CC CC CC 8B FF 55 8B EC 6A 00 FF 15 8C 90 44 00 }
        $code_064_1 = { E3 01 81 EB 96 66 8A 64 83 FB 00 0F 84 07 00 00 }
        $code_064_2 = { 18 92 44 00 50 FF 15 10 92 44 00 5D C3 8B FF 55 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or ($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_2 at (pe.entry_point + 64))))
}

rule Virus_WinPE_FileInfector
{
    meta:
        description = "Shared family entry-point code clusters for Virus_WinPE_FileInfector"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 68 14 00 00 00 68 00 00 00 00 68 6C 56 40 00 E8 }
        $ep_2 = { 55 8B EC 6A FF 68 D0 70 40 00 68 6C 4E 40 00 64 }
        $code_032_3 = { 39 45 08 75 0D FF 75 0C 50 E8 6E 0B 00 00 59 59 }
        $code_048_1 = { 68 00 00 00 00 E8 E2 0F 00 00 A3 6C 56 40 00 E8 }
        $code_064_2 = { 78 A9 40 00 C1 E1 08 03 CA 89 0D 74 A9 40 00 C1 }
        $code_080_1 = { 12 00 00 E8 58 11 00 00 BA 42 50 40 00 8D 0D 78 }
        $code_096_2 = { 11 83 3D 90 56 1A 10 00 75 08 89 75 E0 E9 39 02 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_3 at (pe.entry_point + 32) and $code_096_2 at (pe.entry_point + 96))))
}

rule Virus_WinPE_General
{
    meta:
        description = "Shared family entry-point code clusters for Virus_WinPE_General"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { BE 88 01 40 00 AD 8B F8 95 AD 91 F3 A5 AD B5 1C }
        $ep_2 = { E8 FB 5F 00 00 E8 2B 60 00 00 E8 5C 60 00 00 E8 }
        $code_064_1 = { 01 E3 29 8B D7 2B 55 0C 8A 2A 33 D2 84 E9 0F 95 }
        $code_064_2 = { F1 62 00 00 E8 24 65 00 00 E8 FF 65 00 00 E8 06 }
        $code_096_2 = { 00 00 EF E8 15 6B 00 00 E8 EB 6D 00 00 F3 E8 1F }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or ($ep_2 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64) and $code_096_2 at (pe.entry_point + 96))))
}

rule Virus_WinPE_Hublo
{
    meta:
        description = "Shared family entry-point code clusters for Virus_WinPE_Hublo"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 60 9C E8 00 00 00 00 5D 81 ED 07 10 40 00 8D B5 }
        $code_032_1 = { E8 02 00 00 00 EB 33 C8 00 00 00 60 BB FF FF FF }
        $code_064_1 = { 01 00 05 C5 16 01 00 31 D2 F7 F3 AD 31 D0 AB E2 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))))
}

rule Virus_WinPE_Jadtre
{
    meta:
        description = "Shared family entry-point code clusters for Virus_WinPE_Jadtre"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_5 = { 55 8B EC 83 EC 70 83 65 CC 00 83 65 D4 00 83 65 }
        $ep_6 = { 55 8B EC 81 EC 84 00 00 00 64 FF 35 30 00 00 00 }
        $code_016_1 = { DC 89 45 F0 89 45 EC 89 45 F8 89 45 F4 89 45 E0 }
        $code_048_2 = { 00 5A B9 3E 02 00 00 83 C2 0F 80 32 F7 42 E2 FA }
        $code_064_1 = { 00 00 00 00 58 05 25 02 00 00 89 45 FC 64 A1 30 }
        $code_064_4 = { 35 30 00 00 00 58 89 45 E0 8B 45 E0 8B 40 0C 8B }
        $code_080_1 = { 00 00 00 89 45 D8 8B 45 FC C7 00 83 C4 04 E9 8B }
        $code_080_5 = { 08 89 45 F4 8B 45 F4 8B 40 3C 8B 4D F4 8B 55 F4 }
        $code_112_1 = { 40 1C 8B 00 8B 40 08 8B 48 3C 8B 4C 01 78 03 C8 }
        $code_112_2 = { F6 8F 7E A2 17 7C B2 17 7C BA 03 F4 BF D7 7E BA }
        $code_176_2 = { B8 83 65 8C 00 EB 07 8B 45 8C 40 89 45 8C 8B 45 }
        $code_240_3 = { 55 84 8B 45 84 81 38 47 65 74 4D 75 6A 8B 45 84 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_016_1 at (pe.entry_point + 16) and $code_064_1 at (pe.entry_point + 64) and $code_112_1 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_048_2 at (pe.entry_point + 48) and $code_112_2 at (pe.entry_point + 112))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_176_2 at (pe.entry_point + 176) and $code_240_3 at (pe.entry_point + 240))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_5 at (pe.entry_point + 0) and $code_064_4 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_6 at (pe.entry_point + 0) and $code_080_5 at (pe.entry_point + 80))))
}

rule Virus_WinPE_Phorpiex
{
    meta:
        description = "Shared family entry-point code clusters for Virus_WinPE_Phorpiex"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 81 EC 70 09 00 00 E8 A2 0C 00 00 89 85 }
        $code_064_1 = { 83 BD CC F8 FF FF 00 75 05 E9 F9 06 00 00 8B 8D }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Virus_WinPE_Sality
{
    meta:
        description = "Shared family entry-point code clusters for Virus_WinPE_Sality"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_048_1 = { FC 83 C0 05 89 45 FC 8B 4D FC 83 C1 06 89 4D FC }
        $code_080_1 = { 45 FC 8B 4D FC 83 C1 09 89 4D FC 8B 55 FC 83 C2 }
        $code_112_1 = { 00 FF 15 08 10 40 00 33 C0 8B E5 5D C3 CC CC CC }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80) and $code_112_1 at (pe.entry_point + 112))))
}

rule Virus_WinPE_Ursnif
{
    meta:
        description = "Shared family entry-point code clusters for Virus_WinPE_Ursnif"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 83 EC 28 53 55 56 57 FF 15 20 20 40 00 A3 10 30 }
        $code_064_1 = { 33 C0 66 89 44 24 34 33 FF 8B DD C1 EB 1C 80 E3 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Virus_WinPE_VBCode
{
    meta:
        description = "Shared family entry-point code clusters for Virus_WinPE_VBCode"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 68 E0 24 40 00 E8 EE FF FF FF 00 00 00 00 00 00 }
        $ep_2 = { 68 18 4E 40 00 E8 EE FF FF FF 00 00 00 00 00 00 }
        $ep_3 = { B4 48 73 35 0F 48 73 BC E9 46 73 FE 47 3B 73 D7 }
        $code_032_1 = { C3 85 78 4D A8 2A 16 12 07 FD E9 03 00 00 00 00 }
        $code_032_2 = { 5A 63 DD 40 AC F9 8B D6 A6 A0 2A 4B 00 00 00 00 }
        $code_064_1 = { 69 73 6B 42 69 6E 64 65 72 00 20 20 00 00 00 00 }
        $code_064_2 = { 69 6E 64 65 72 00 6F 54 6F 20 65 78 00 00 00 00 }
        $code_096_3 = { 00 14 00 2F 42 40 00 8A 42 40 00 36 42 40 00 00 }
        $code_128_1 = { 36 40 00 DB 36 40 00 E8 36 40 00 06 37 40 00 18 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_2 at (pe.entry_point + 0) and $code_032_2 at (pe.entry_point + 32) and $code_064_2 at (pe.entry_point + 64))
                or ($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))
                or ($ep_3 at (pe.entry_point + 0) and $code_096_3 at (pe.entry_point + 96) and $code_128_1 at (pe.entry_point + 128))))
}

rule Virus_WinPE_Virut
{
    meta:
        description = "Shared family entry-point code clusters for Virus_WinPE_Virut"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_032_1 = { 90 2C 01 00 00 89 44 24 1C BB 4E 03 00 00 8D B5 }
        $code_240_1 = { 13 C9 E8 E7 FF FF FF 72 F2 C3 00 00 00 00 00 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_1 at (pe.entry_point + 32) and $code_240_1 at (pe.entry_point + 240))))
}

rule Virus_WinPE_Xbminer
{
    meta:
        description = "Shared family entry-point code clusters for Virus_WinPE_Xbminer"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 60 BE 00 C0 43 00 8D BE 00 50 FC FF 57 83 CD FF }
        $code_096_1 = { C0 75 08 6A 1C E8 C3 00 00 00 59 E8 1F 35 00 00 }
        $code_160_1 = { E8 F6 2E 00 00 E8 E1 18 00 00 89 75 D0 8D 45 A4 }
        $code_208_1 = { FF FF 5E 89 F7 B9 6E 0A 00 00 8A 07 47 2C E8 3C }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_096_1 at (pe.entry_point + 96) and $code_160_1 at (pe.entry_point + 160))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_208_1 at (pe.entry_point + 208))))
}

rule Worm_WinPE_Agent
{
    meta:
        description = "Shared family entry-point code clusters for Worm_WinPE_Agent"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_2 = { 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 9C }
        $ep_3 = { E8 58 B1 00 00 E9 17 FE FF FF B8 AB E4 45 00 A3 }
        $code_064_2 = { 00 C7 05 50 4E 47 00 25 E4 45 00 C7 05 54 4E 47 }
        $code_080_1 = { 16 80 02 00 00 04 2A CC 03 30 01 00 07 00 00 00 }
        $code_080_2 = { 55 89 E5 5D C3 90 55 89 E5 5D C3 90 55 89 E5 8B }
        $code_160_1 = { 16 80 12 00 00 04 2A CC 03 30 01 00 07 00 00 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.data_directories[14].size > 0 and $code_080_1 at (pe.entry_point + 80) and $code_160_1 at (pe.entry_point + 160))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_080_2 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))))
}

rule Worm_WinPE_Autorun
{
    meta:
        description = "Shared family entry-point code clusters for Worm_WinPE_Autorun"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 68 7C 9F 40 00 E8 EE FF FF FF 00 00 00 00 00 00 }
        $ep_3 = { 68 A8 44 40 00 E8 EE FF FF FF 00 00 00 00 00 00 }
        $ep_6 = { 55 89 E5 6A FF 68 DC 18 41 00 68 D8 5D 40 00 64 }
        $ep_9 = { 68 8C 15 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 }
        $ep_11 = { 68 10 EF 56 00 E8 F0 FF FF FF 00 00 00 00 00 00 }
        $code_016_5 = { 94 49 00 E8 78 FE FF FF 90 8D B4 26 00 00 00 00 }
        $code_016_6 = { 00 8B C7 E8 45 F2 FF FF 89 65 E8 8B F4 89 3E 56 }
        $code_016_7 = { 12 54 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 }
        $code_032_1 = { 39 A4 8E 44 9D 85 14 FF 70 1A 1D D7 00 00 00 00 }
        $code_032_3 = { 82 51 FD 41 8A 16 C2 FC DB 32 21 97 00 00 00 00 }
        $code_032_10 = { 52 83 C0 48 BA C4 FF 5E 69 8D 0E 28 00 00 00 00 }
        $code_064_1 = { 70 64 61 74 65 00 41 00 20 08 41 00 00 00 00 00 }
        $code_064_6 = { 01 E8 5A 11 00 00 59 C7 45 FC 00 00 00 00 E8 7D }
        $code_080_3 = { 12 6E 52 2E 48 A2 45 EB 3D 09 C5 9C 57 AE 72 2C }
        $code_080_5 = { 0A 00 00 00 F7 F3 89 C7 8B 44 24 18 89 D1 31 D2 }
        $code_080_8 = { 55 89 E5 83 EC 18 83 E4 F0 B8 00 00 00 00 83 C0 }
        $code_080_9 = { FF CC 31 00 08 37 C8 9B FA A3 96 5F 43 91 55 58 }
        $code_112_5 = { A0 42 00 FF D7 66 81 38 4D 5A 75 1F 8B 48 3C 03 }
        $code_160_8 = { 00 EF 01 00 00 3F 00 00 00 00 05 00 66 4D 61 69 }
        $code_176_1 = { 09 00 00 00 73 49 52 43 34 2E 65 78 65 00 00 00 }
        $code_192_7 = { 05 00 46 6F 72 6D 31 00 26 00 27 00 2E 00 35 00 }
        $code_240_2 = { 6F 72 67 00 FF FF FF FF 03 00 00 00 2A 2E 2A 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64))
                or (pe.imports("wsock32.dll", "WSAStartup") and pe.imports("wsock32.dll", "connect") and $code_176_1 at (pe.entry_point + 176) and $code_240_2 at (pe.entry_point + 240))
                or ($ep_3 at (pe.entry_point + 0) and $code_032_3 at (pe.entry_point + 32) and $code_080_3 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_5 at (pe.entry_point + 16) and $code_080_5 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_6 at (pe.entry_point + 16) and $code_112_5 at (pe.entry_point + 112))
                or (pe.data_directories[14].size > 0 and $code_016_7 at (pe.entry_point + 16) and $code_080_8 at (pe.entry_point + 80))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_6 at (pe.entry_point + 0) and $code_064_6 at (pe.entry_point + 64))
                or ($ep_9 at (pe.entry_point + 0) and $code_160_8 at (pe.entry_point + 160) and $code_192_7 at (pe.entry_point + 192))
                or ($ep_11 at (pe.entry_point + 0) and $code_032_10 at (pe.entry_point + 32) and $code_080_9 at (pe.entry_point + 80))))
}

rule Worm_WinPE_FakeDoc
{
    meta:
        description = "Shared family entry-point code clusters for Worm_WinPE_FakeDoc"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { E8 8F E6 00 00 E9 7B FE FF FF 3B 0D A0 EE 4A 00 }
        $code_064_1 = { 00 00 C7 06 54 D8 49 00 8B C6 5E 5D C2 04 00 55 }
        $code_128_1 = { 3A 87 AC 17 5A 6B 72 81 EC 04 00 00 00 89 14 24 }
        $code_128_2 = { EC 04 00 00 00 89 14 24 BA 3D B1 46 A3 68 23 02 }
        $code_128_3 = { 67 1A 45 12 3A 87 AC 17 5A 6B 72 81 EC 04 00 00 }
        $code_128_4 = { 1A 45 12 3A 87 AC 17 5A 6B 72 81 EC 04 00 00 00 }
        $code_144_3 = { 3A 87 AC 17 5A 6B 72 81 EC 04 00 00 00 89 14 24 }
        $code_144_4 = { 17 5A 6B 72 81 EC 04 00 00 00 89 14 24 BA 3D B1 }
        $code_144_6 = { 12 3A 87 AC 17 5A 6B 72 81 EC 04 00 00 00 89 14 }
        $code_160_3 = { 88 42 8E 15 58 B9 5F 62 ED 79 53 BB 01 00 00 00 }
        $code_160_5 = { 1A 45 12 3A 87 AC 17 5A 6B 72 81 EC 04 00 00 00 }
        $code_160_6 = { ED 79 53 BB 01 00 00 00 01 D9 5B 57 BF F2 76 AD }
        $code_160_7 = { 81 04 24 88 42 8E 15 58 B9 5F 62 ED 79 53 BB 01 }
        $code_160_8 = { 67 1A 45 12 3A 87 AC 17 5A 6B 72 81 EC 04 00 00 }
        $code_160_9 = { 5A 6B 72 81 EC 04 00 00 00 89 14 24 BA 3D B1 46 }
        $code_160_10 = { 45 12 3A 87 AC 17 5A 6B 72 81 EC 04 00 00 00 89 }
        $code_160_12 = { 24 81 04 24 88 42 8E 15 58 B9 5F 62 ED 79 53 BB }
        $code_160_13 = { 00 00 00 89 14 24 BA 3D B1 46 A3 68 23 02 00 00 }
        $code_176_3 = { 88 42 8E 15 58 B9 5F 62 ED 79 53 BB 01 00 00 00 }
        $code_176_4 = { 15 58 B9 5F 62 ED 79 53 BB 01 00 00 00 01 D9 5B }
        $code_176_9 = { 24 88 42 8E 15 58 B9 5F 62 ED 79 53 BB 01 00 00 }
        $code_192_2 = { CE 2F 05 CA 67 13 6C 29 C8 2D CA 67 13 6C 8B 14 }
        $code_192_3 = { 81 04 24 88 42 8E 15 58 B9 5F 62 ED 79 53 BB 01 }
        $code_192_6 = { F1 1A 56 CE 2F 05 CA 67 13 6C 29 C8 2D CA 67 13 }
        $code_192_7 = { C8 2D CA 67 13 6C 8B 14 24 83 C4 04 00 00 00 00 }
        $code_192_8 = { 81 F1 1A 56 CE 2F 05 CA 67 13 6C 29 C8 2D CA 67 }
        $code_192_9 = { 58 B9 5F 62 ED 79 53 BB 01 00 00 00 01 D9 5B 57 }
        $code_192_10 = { 53 BB 01 00 00 00 01 D9 5B 57 BF F2 76 AD 43 31 }
        $code_192_11 = { 24 81 04 24 88 42 8E 15 58 B9 5F 62 ED 79 53 BB }
        $code_192_12 = { 04 24 88 42 8E 15 58 B9 5F 62 ED 79 53 BB 01 00 }
        $code_208_2 = { CE 2F 05 CA 67 13 6C 29 C8 2D CA 67 13 6C 8B 14 }
        $code_208_3 = { CA 67 13 6C 29 C8 2D CA 67 13 6C 8B 14 24 83 C4 }
        $code_208_9 = { 56 CE 2F 05 CA 67 13 6C 29 C8 2D CA 67 13 6C 8B }
        $code_224_2 = { F1 1A 56 CE 2F 05 CA 67 13 6C 29 C8 2D CA 67 13 }
        $code_224_5 = { CA 67 13 6C 8B 14 24 83 C4 04 00 00 00 00 00 00 }
        $code_224_6 = { 81 F1 1A 56 CE 2F 05 CA 67 13 6C 29 C8 2D CA 67 }
        $code_224_7 = { 67 13 6C 29 C8 2D CA 67 13 6C 8B 14 24 83 C4 04 }
        $code_224_8 = { 1A 56 CE 2F 05 CA 67 13 6C 29 C8 2D CA 67 13 6C }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))
                or ($code_144_3 at (pe.entry_point + 144) and $code_176_3 at (pe.entry_point + 176) and $code_208_2 at (pe.entry_point + 208))
                or ($code_144_4 at (pe.entry_point + 144) and $code_176_4 at (pe.entry_point + 176) and $code_208_3 at (pe.entry_point + 208))
                or ($code_160_5 at (pe.entry_point + 160) and $code_192_3 at (pe.entry_point + 192) and $code_224_2 at (pe.entry_point + 224))
                or ($code_128_1 at (pe.entry_point + 128) and $code_160_3 at (pe.entry_point + 160) and $code_192_2 at (pe.entry_point + 192))
                or ($code_128_2 at (pe.entry_point + 128) and $code_160_6 at (pe.entry_point + 160) and $code_192_7 at (pe.entry_point + 192))
                or ($code_160_8 at (pe.entry_point + 160) and $code_192_11 at (pe.entry_point + 192) and $code_224_6 at (pe.entry_point + 224))
                or ($code_144_6 at (pe.entry_point + 144) and $code_176_9 at (pe.entry_point + 176) and $code_208_9 at (pe.entry_point + 208))
                or ($code_160_9 at (pe.entry_point + 160) and $code_192_9 at (pe.entry_point + 192) and $code_224_7 at (pe.entry_point + 224))
                or ($code_160_13 at (pe.entry_point + 160) and $code_192_10 at (pe.entry_point + 192) and $code_224_5 at (pe.entry_point + 224))
                or ($code_160_10 at (pe.entry_point + 160) and $code_192_12 at (pe.entry_point + 192) and $code_224_8 at (pe.entry_point + 224))
                or ($code_128_4 at (pe.entry_point + 128) and $code_160_7 at (pe.entry_point + 160) and $code_192_6 at (pe.entry_point + 192))
                or ($code_128_3 at (pe.entry_point + 128) and $code_160_12 at (pe.entry_point + 160) and $code_192_8 at (pe.entry_point + 192))))
}

rule Worm_WinPE_FakeFolder
{
    meta:
        description = "Shared family entry-point code clusters for Worm_WinPE_FakeFolder"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_1 = { 60 BE 00 40 42 00 8D BE 00 D0 FD FF 57 83 CD FF }
        $code_208_1 = { FF FF 5E 89 F7 B9 E3 01 00 00 8A 07 47 2C E8 3C }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_208_1 at (pe.entry_point + 208))))
}

rule Worm_WinPE_Gamarue
{
    meta:
        description = "Shared family entry-point code clusters for Worm_WinPE_Gamarue"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 6A FF 68 B8 70 40 00 68 58 3E 40 00 64 }
        $code_064_1 = { 14 07 47 00 C1 E1 08 03 CA 89 0D 10 07 47 00 C1 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Worm_WinPE_Ganelp
{
    meta:
        description = "Shared family entry-point code clusters for Worm_WinPE_Ganelp"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_032_1 = { 53 56 57 89 65 E8 FF 15 B0 A2 43 00 A3 64 86 43 }
        $code_032_2 = { 53 56 57 89 65 E8 FF 15 D0 D2 43 00 A3 EC A7 43 }
        $code_032_3 = { 53 56 57 89 65 E8 FF 15 B8 F2 43 00 A3 E0 CC 43 }
        $code_096_1 = { 70 86 43 00 89 15 68 86 43 00 A1 64 86 43 00 C1 }
        $code_096_2 = { F8 A7 43 00 89 15 F0 A7 43 00 A1 EC A7 43 00 C1 }
        $code_096_3 = { EC CC 43 00 89 15 E4 CC 43 00 A1 E0 CC 43 00 C1 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_1 at (pe.entry_point + 32) and $code_096_1 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_2 at (pe.entry_point + 32) and $code_096_2 at (pe.entry_point + 96))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_3 at (pe.entry_point + 32) and $code_096_3 at (pe.entry_point + 96))))
}

rule Worm_WinPE_General
{
    meta:
        description = "Shared family entry-point code clusters for Worm_WinPE_General"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $ep_2 = { E9 59 01 00 00 90 7C 4F F1 D1 0F 0E A6 72 3C 0E }
        $ep_3 = { DE 7C 73 25 39 F4 3E 10 DA 9C 04 11 ED F2 38 2C }
        $code_064_2 = { 44 10 81 3E C5 45 F3 29 AA EF 39 3C 87 8B 8D 0A }
        $code_064_3 = { 1E 84 F8 7A EF 72 1F 0D E0 2A 82 15 C0 38 72 19 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_3 at (pe.entry_point + 0) and $code_064_2 at (pe.entry_point + 64))
                or (pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_2 at (pe.entry_point + 0) and $code_064_3 at (pe.entry_point + 64))))
}

rule Worm_WinPE_Grenam
{
    meta:
        description = "Shared family entry-point code clusters for Worm_WinPE_Grenam"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 83 C4 F0 53 B8 14 0E 47 00 E8 43 4A F9 }
        $code_064_1 = { 8B 0D 68 53 47 00 8B 03 8B 15 90 05 47 00 E8 E9 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Worm_WinPE_Mira
{
    meta:
        description = "Shared family entry-point code clusters for Worm_WinPE_Mira"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 4C }
        $code_032_1 = { 55 8B 0D 88 62 44 00 89 E5 5D FF E1 8D 74 26 00 }
        $code_080_1 = { 55 89 E5 83 EC 28 8B 45 10 89 04 24 E8 EF FD 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_032_1 at (pe.entry_point + 32) and $code_080_1 at (pe.entry_point + 80))))
}

rule Worm_WinPE_Pintu
{
    meta:
        description = "Shared family entry-point code clusters for Worm_WinPE_Pintu"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 55 8B EC 83 C4 F0 53 B8 64 5E 4A 00 E8 83 EB F5 }
        $code_064_1 = { 8B 0D F0 E1 4A 00 8B 03 8B 15 F8 54 4A 00 E8 99 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Worm_WinPE_Stration
{
    meta:
        description = "Shared family entry-point code clusters for Worm_WinPE_Stration"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 6A 60 68 98 E5 42 00 E8 AF 08 00 00 BF 94 00 00 }
        $code_064_1 = { 8B 76 0C 81 E6 FF 7F 00 00 89 35 18 22 43 00 83 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $ep_1 at (pe.entry_point + 0) and $code_064_1 at (pe.entry_point + 64))))
}

rule Worm_WinPE_Vobfus
{
    meta:
        description = "Shared family entry-point code clusters for Worm_WinPE_Vobfus"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $ep_1 = { 68 B8 11 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 }
        $code_080_1 = { 25 05 80 C7 43 A0 0C 0D 11 32 41 9B 49 95 7E 5D }
        $code_176_1 = { 32 00 0D 01 05 00 46 6F 72 6D 32 00 19 01 00 42 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($ep_1 at (pe.entry_point + 0) and $code_080_1 at (pe.entry_point + 80) and $code_176_1 at (pe.entry_point + 176))))
}

rule Adware_WinPE_CrossRider
{
    meta:
        description = "Shared family code windows near entry point for Adware_WinPE_CrossRider"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_032_1 = { C7 04 24 00 00 00 00 FF 15 98 94 42 00 56 A3 40 }
        $code_112_1 = { AC 94 42 00 83 EC 14 C7 44 24 04 02 B3 40 00 C7 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_032_1 at (pe.entry_point + 32) and $code_112_1 at (pe.entry_point + 112))))
}

rule Backdoor_Win64_CobaltStrike
{
    meta:
        description = "Shared family code windows near entry point for Backdoor_Win64_CobaltStrike"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_016_1 = { FF FF CC CC 48 83 EC 28 E8 E7 0D 00 00 85 C0 74 }
        $code_048_1 = { 48 3B C8 74 14 33 C0 F0 48 0F B1 0D B8 0C 05 00 }
        $code_080_1 = { 40 53 48 83 EC 20 0F B6 05 A3 0C 05 00 85 C9 BB }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_016_1 at (pe.entry_point + 16) and $code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80))))
}

rule Backdoor_WinPE_DarkKomet
{
    meta:
        description = "Shared family code windows near entry point for Backdoor_WinPE_DarkKomet"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_016_1 = { 53 56 57 B8 9C 20 40 00 E8 6B FA FF FF 33 C0 55 }
        $code_048_1 = { 23 40 00 E8 44 FE FF FF 8B 45 EC E8 14 FF FF FF }
        $code_080_1 = { 55 E0 8B C3 E8 D3 FE FF FF 8B 4D E0 8D 45 E4 BA }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_016_1 at (pe.entry_point + 16) and $code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80))))
}

rule Exploit_WinPE_EquationDrug
{
    meta:
        description = "Shared family code windows near entry point for Exploit_WinPE_EquationDrug"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_016_1 = { 8B F8 8B DA 48 8B F1 83 FA 01 75 05 E8 1B 27 00 }
        $code_080_1 = { 48 08 57 48 83 EC 20 48 8B CA 48 8B DA E8 12 34 }
        $code_192_1 = { C8 02 89 43 18 A9 0C 01 00 00 75 2F E8 8F 31 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80) and $code_192_1 at (pe.entry_point + 192))))
}

rule Exploit_WinPE_Vulndriver
{
    meta:
        description = "Shared family code windows near entry point for Exploit_WinPE_Vulndriver"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $code_016_1 = { 48 8D A8 48 FE FF FF 48 81 EC B0 02 00 00 48 8B }
        $code_048_1 = { 8B D9 48 8D 0D C7 2B 00 00 E8 52 05 00 00 66 0F }
        $code_080_1 = { 00 00 33 D2 48 83 64 24 40 00 41 B8 AA 00 00 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_016_1 at (pe.entry_point + 16) and $code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80))))
}

rule HackTool_WinPE_RemoteAdmin
{
    meta:
        description = "Shared family code windows near entry point for HackTool_WinPE_RemoteAdmin"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $code_016_1 = { 15 58 B0 40 00 FF 75 08 FF 15 54 B0 40 00 68 09 }
        $code_080_1 = { 00 89 0D 7C 18 41 00 89 15 78 18 41 00 89 1D 74 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80))))
}

rule Ransom_WinPE_LockBit
{
    meta:
        description = "Shared family code windows near entry point for Ransom_WinPE_LockBit"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_016_1 = { FF FF CC CC E9 E7 05 00 00 CC CC CC 48 83 EC 28 }
        $code_112_1 = { 00 84 C0 75 04 32 C0 EB 14 E8 6A 56 00 00 84 C0 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_112_1 at (pe.entry_point + 112))))
}

rule Ransom_WinPE_Qilin
{
    meta:
        description = "Shared family code windows near entry point for Ransom_WinPE_Qilin"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_016_1 = { 83 EC 1C 8B 44 24 20 89 04 24 E8 D1 A9 03 00 83 }
        $code_128_1 = { 29 60 44 00 89 1C 24 FF D7 83 EC 08 A3 04 50 44 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_128_1 at (pe.entry_point + 128))))
}

rule Rootkit_WinPE_Winnti
{
    meta:
        description = "Shared family code windows near entry point for Rootkit_WinPE_Winnti"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_064_2 = { 85 C0 75 04 33 C0 EB 4E 57 56 53 E8 DF EC FF FF }
        $code_160_2 = { 50 00 10 FF 25 54 50 00 10 CC CC CC CC CC CC 83 }
        $code_176_1 = { 24 3C 56 57 8B 7C 24 48 89 4C 24 0C 89 44 24 08 }
        $code_240_1 = { 75 47 8D 54 24 08 6A 04 52 E8 15 02 00 00 8B F0 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_176_1 at (pe.entry_point + 176) and $code_240_1 at (pe.entry_point + 240))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_064_2 at (pe.entry_point + 64) and $code_160_2 at (pe.entry_point + 160))))
}

rule TrojanDropper_Win64_Agent
{
    meta:
        description = "Shared family code windows near entry point for TrojanDropper_Win64_Agent"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "64-bit Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $code_032_1 = { 48 8D 45 FC 49 89 C2 4C 89 D1 4C 89 DA E8 5C 01 }
        $code_064_1 = { 7A 01 00 00 B8 01 00 00 00 49 89 C2 4C 89 D1 E8 }
        $code_096_1 = { 00 49 89 C2 4C 89 D1 4C 89 DA E8 5F 01 00 00 48 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_032_1 at (pe.entry_point + 32) and $code_064_1 at (pe.entry_point + 64) and $code_096_1 at (pe.entry_point + 96))))
}

rule TrojanSpy_MSIL_PwStealer
{
    meta:
        description = "Shared family code windows near entry point for TrojanSpy_MSIL_PwStealer"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "managed Windows PE assemblies; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $code_016_1 = { 69 00 6C 00 6C 00 50 00 72 00 6F 00 66 00 69 00 }
        $code_080_1 = { 69 00 72 00 6F 00 6E 00 6D 00 65 00 6E 00 74 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.data_directories[14].size > 0 and $code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80))))
}

rule TrojanSpy_Python_Keylogger
{
    meta:
        description = "Shared family code windows near entry point for TrojanSpy_Python_Keylogger"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples containing Python artifacts or packaged payloads; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $code_176_1 = { 00 5B 5E 5F C2 10 00 55 8B EC 6A 00 FF 15 60 00 }
        $code_240_1 = { C0 74 05 6A 02 59 CD 29 A3 60 9B 43 00 89 0D 5C }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_176_1 at (pe.entry_point + 176) and $code_240_1 at (pe.entry_point + 240))))
}

rule TrojanSpy_WinPE_ClipBanker
{
    meta:
        description = "Shared family code windows near entry point for TrojanSpy_WinPE_ClipBanker"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_096_1 = { C0 75 08 6A 1C E8 C3 00 00 00 59 E8 07 28 00 00 }
        $code_160_1 = { E8 E9 2B 00 00 E8 37 01 00 00 89 75 D0 8D 45 A4 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_096_1 at (pe.entry_point + 96) and $code_160_1 at (pe.entry_point + 160))))
}

rule TrojanSpy_WinPE_Danabot
{
    meta:
        description = "Shared family code windows near entry point for TrojanSpy_WinPE_Danabot"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_048_1 = { FF FF 33 C0 5A 59 59 64 89 10 68 F3 B9 52 00 C3 }
        $code_048_2 = { FF FF 33 C0 5A 59 59 64 89 10 68 F3 C9 52 00 C3 }
        $code_048_3 = { FF FF 33 C0 5A 59 59 64 89 10 68 F3 A9 52 00 C3 }
        $code_144_1 = { 00 00 00 00 00 00 00 00 DE 24 DF CE A4 80 7D 44 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_048_1 at (pe.entry_point + 48) and $code_144_1 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_048_2 at (pe.entry_point + 48) and $code_144_1 at (pe.entry_point + 144))
                or (pe.imports("kernel32.dll", "VirtualProtect") and pe.imports("kernel32.dll", "GetProcAddress") and $code_048_3 at (pe.entry_point + 48) and $code_144_1 at (pe.entry_point + 144))))
}

rule TrojanSpy_WinPE_LummaStealer
{
    meta:
        description = "Shared family code windows near entry point for TrojanSpy_WinPE_LummaStealer"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_096_1 = { 06 00 00 85 C0 74 62 BA BF 77 0C D8 8B C8 E8 3D }
        $code_128_1 = { FF D3 8B F0 3B F7 72 0E 8B CE 2B CF 81 F9 E8 03 }
        $code_160_1 = { D7 3B F7 5F 8D 42 FF 0F 42 D0 2B CA 81 FA E8 03 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_096_1 at (pe.entry_point + 96) and $code_128_1 at (pe.entry_point + 128) and $code_160_1 at (pe.entry_point + 160))))
}

rule TrojanSpy_WinPE_Zbot
{
    meta:
        description = "Shared family code windows near entry point for TrojanSpy_WinPE_Zbot"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_048_1 = { DD 8B 48 3C 03 C8 81 39 50 45 00 00 75 D0 8B 49 }
        $code_112_1 = { 00 00 5B 5D C2 20 00 55 8B EC 56 8B 75 0C 57 8B }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_048_1 at (pe.entry_point + 48) and $code_112_1 at (pe.entry_point + 112))))
}

rule Trojan_AutoIT_Injector
{
    meta:
        description = "Shared family code windows near entry point for Trojan_AutoIT_Injector"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples containing AutoIt-related artifacts or payloads; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $code_016_1 = { 08 8B F1 E8 58 00 00 00 C7 06 10 FE 49 00 8B C6 }
        $code_096_1 = { 08 00 C7 41 04 34 FE 49 00 C7 01 2C FE 49 00 C3 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_016_1 at (pe.entry_point + 16) and $code_096_1 at (pe.entry_point + 96))))
}

rule Trojan_WinPE_DllHijack
{
    meta:
        description = "Shared family code windows near entry point for Trojan_WinPE_DllHijack"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $code_048_1 = { 58 31 D2 E8 C8 06 00 00 44 8B 4C 24 58 49 89 F0 }
        $code_048_2 = { 58 31 D2 E8 08 07 00 00 44 8B 4C 24 58 49 89 F0 }
        $code_176_1 = { 49 89 F0 BA 01 00 00 00 48 89 D9 E8 40 06 00 00 }
        $code_176_2 = { 49 89 F0 BA 01 00 00 00 48 89 D9 E8 80 06 00 00 }
        $code_208_1 = { 89 54 24 2C E8 27 06 00 00 49 89 F0 31 D2 48 89 }
        $code_208_2 = { 89 54 24 2C E8 67 06 00 00 49 89 F0 31 D2 48 89 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_048_1 at (pe.entry_point + 48) and $code_176_1 at (pe.entry_point + 176) and $code_208_1 at (pe.entry_point + 208))
                or ($code_048_2 at (pe.entry_point + 48) and $code_176_2 at (pe.entry_point + 176) and $code_208_2 at (pe.entry_point + 208))))
}

rule Trojan_WinPE_KillMBR
{
    meta:
        description = "Shared family code windows near entry point for Trojan_WinPE_KillMBR"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "generic capability label from rule taxonomy; not a verified malware-family attribution"
    strings:
        $code_016_1 = { E8 89 45 E4 89 45 EC B8 DC 88 40 00 E8 3B BD FF }
        $code_048_1 = { 9C 9E 40 00 BF FC B7 40 00 B9 80 00 00 00 F3 A5 }
        $code_080_1 = { 04 8C 40 00 E8 33 CD FF FF A2 6B B8 40 00 B8 10 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_016_1 at (pe.entry_point + 16) and $code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80))))
}

rule Trojan_WinPE_RService
{
    meta:
        description = "Shared family code windows near entry point for Trojan_WinPE_RService"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_016_1 = { C7 44 24 10 00 8A 40 00 33 F6 C6 44 24 14 20 FF }
        $code_080_1 = { 24 38 50 53 68 93 8A 40 00 FF 15 58 81 40 00 68 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80))))
}

rule Trojan_WinPE_Swrort
{
    meta:
        description = "Shared family code windows near entry point for Trojan_WinPE_Swrort"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_064_1 = { 20 41 00 85 C0 74 05 6A 02 59 CD 29 A3 C0 9F 41 }
        $code_096_1 = { 9F 41 00 89 35 B0 9F 41 00 89 3D AC 9F 41 00 66 }
        $code_128_1 = { A8 9F 41 00 66 8C 05 A4 9F 41 00 66 8C 25 A0 9F }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_064_1 at (pe.entry_point + 64) and $code_096_1 at (pe.entry_point + 96) and $code_128_1 at (pe.entry_point + 128))))
}

rule Trojan_WinPE_Zbot
{
    meta:
        description = "Shared family code windows near entry point for Trojan_WinPE_Zbot"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_016_1 = { 84 C0 0F 84 D4 00 00 00 68 07 80 00 00 88 5D F0 }
        $code_080_1 = { 85 C9 74 32 66 83 39 2D 75 2C 0F B7 49 02 83 F9 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "VirtualAllocEx") and pe.imports("kernel32.dll", "WriteProcessMemory") and $code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80))))
}

rule VirTool_WinPE_WannaMine
{
    meta:
        description = "Shared family code windows near entry point for VirTool_WinPE_WannaMine"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_016_1 = { 45 08 33 C9 3B 04 CD E8 80 9D 00 74 13 41 83 F9 }
        $code_080_1 = { 00 85 C0 75 06 B8 50 82 9D 00 C3 83 C0 08 C3 E8 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            ((pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress") and $code_016_1 at (pe.entry_point + 16) and $code_080_1 at (pe.entry_point + 80))))
}

rule Virus_WinPE_Zbot
{
    meta:
        description = "Shared family code windows near entry point for Virus_WinPE_Zbot"
        author = "PYAS Security"
        date = "2026-09-09"
        scope = "Windows PE samples; may also match bundled or embedded payloads"
        evidence = "family-dependent compound conditions; corpus validation recorded separately"
        attribution = "family label follows rule taxonomy; not independently verified by embedded provenance"
    strings:
        $code_016_1 = { 69 2E 64 6C 6C 00 61 64 76 61 70 69 33 32 2E 64 }
        $code_048_1 = { 66 74 77 61 72 65 5C 4D 69 63 72 6F 73 6F 66 74 }
        $code_080_1 = { 72 75 6D 2F 00 55 89 E5 83 EC 04 53 E8 EA 01 00 }
    condition:
        (General_WinPE_ValidPE and
            pe.sections[pe.section_index(pe.entry_point)].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            (($code_016_1 at (pe.entry_point + 16) and $code_048_1 at (pe.entry_point + 48) and $code_080_1 at (pe.entry_point + 80))))
}


rule Trojan_MSIL_HollowingEvasion
{
    meta:
        description = "Managed process replacement and Defender exclusion combined with concealed payload launch"
        author = "PYAS Security"
        date = "2026-09-14"
        scope = "managed Windows PE assemblies; capability-level heuristic"
        evidence = "compound condition requires managed PE structure, process-hollowing APIs, Defender exclusion, hidden execution and payload-loading signals"
        attribution = "capability cluster; not a verified family name"
    strings:
        $hollow_1 = "NtUnmapViewOfSection" ascii fullword
        $hollow_2 = "WriteProcessMemory" ascii fullword
        $hollow_3 = "SetThreadContext" ascii fullword
        $hollow_4 = "ResumeThread" ascii fullword
        $hollow_5 = "VirtualAllocEx" ascii fullword
        $exclude = "Add-MpPreference -ExclusionPath" ascii wide nocase
        $hide_1 = "set_CreateNoWindow" ascii fullword
        $hide_2 = "set_WindowStyle" ascii fullword
        $payload_1 = "FromBase64String" ascii fullword
        $payload_2 = "DownloadData" ascii fullword
        $payload_3 = "CreateDecryptor" ascii fullword
    condition:
        General_WinPE_AnySizePE and pe.data_directories[14].size > 0 and
        all of ($hollow_*) and $exclude and all of ($hide_*) and 1 of ($payload_*)
}

rule Ransom_WinPE_RecoveryDestroyer
{
    meta:
        description = "Ransom demand, shadow-copy deletion, recovery sabotage and cryptographic API cluster"
        author = "PYAS Security"
        date = "2026-09-14"
        scope = "Windows PE samples; capability-level heuristic"
        evidence = "compound condition requires ransom-note, shadow-copy deletion, recovery sabotage, payment, cryptographic and command-execution signals"
        attribution = "capability cluster; not a verified family name"
    strings:
        $note_1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $note_2 = "All your files have been encrypted" ascii wide nocase
        $shadow = "delete shadows" ascii wide nocase
        $recovery_1 = "recoveryenabled no" ascii wide nocase
        $recovery_2 = "bootstatuspolicy ignoreallfailures" ascii wide nocase
        $recovery_3 = "delete catalog" ascii wide nocase
        $pay_1 = "bitcoin" ascii wide nocase
        $pay_2 = ".onion" ascii wide
        $crypto_1 = "CryptEncrypt" ascii
        $crypto_2 = "BCryptEncrypt" ascii
        $crypto_3 = "CreateEncryptor" ascii
        $exec_1 = "cmd.exe" ascii wide nocase
        $exec_2 = "powershell" ascii wide nocase
    condition:
        General_WinPE_AnySizePE and 1 of ($note_*) and $shadow and
        1 of ($recovery_*) and 1 of ($pay_*) and 1 of ($crypto_*) and 1 of ($exec_*) and
        (pe.data_directories[14].size > 0 or
         pe.imports("advapi32.dll", "CryptEncrypt") or pe.imports("bcrypt.dll", "BCryptEncrypt"))
}

rule TrojanSpy_WinPE_DiscordTokenExfil
{
    meta:
        description = "Discord encrypted-token harvesting and account API combined with external exfiltration"
        author = "PYAS Security"
        date = "2026-09-14"
        scope = "Windows PE samples; capability-level heuristic"
        evidence = "compound condition requires Discord token storage, account endpoint, external exfiltration and decryption signals"
        attribution = "capability cluster; not a verified family name"
    strings:
        $token = "dQw4w9WgXcQ:" ascii wide
        $target = "Local Storage" ascii wide
        $key = "os_crypt" ascii wide
        $endpoint = "/users/@me" ascii wide
        $exfil_1 = "api.telegram.org/bot" ascii wide
        $exfil_2 = "discord.com/api/webhooks" ascii wide
        $exfil_3 = "discordapp.com/api/webhooks" ascii wide
        $decrypt_1 = "CryptUnprotectData" ascii
        $decrypt_2 = "ProtectedData" ascii
        $decrypt_3 = "BCryptDecrypt" ascii
    condition:
        General_WinPE_AnySizePE and $token and $target and $key and $endpoint and
        1 of ($exfil_*) and 1 of ($decrypt_*) and
        (pe.data_directories[14].size > 0 or pe.imports("kernel32.dll", "GetProcAddress"))
}

rule TrojanSpy_WinPE_BrowserCredentialExfil
{
    meta:
        description = "Browser decryption targets combined with credential extraction and external upload"
        author = "PYAS Security"
        date = "2026-09-14"
        scope = "Windows PE samples; capability-level heuristic"
        evidence = "compound condition requires browser credential stores, decryption, upload and external exfiltration signals"
        attribution = "capability cluster; not a verified family name"
    strings:
        $credential = "password_value" ascii wide
        $key = "os_crypt" ascii wide
        $cookie = "encrypted_value" ascii wide
        $nss = "PK11SDR_Decrypt" ascii
        $target_1 = "Login Data" ascii wide
        $target_2 = "Local State" ascii wide
        $target_3 = "Web Data" ascii wide
        $exfil_1 = "api.telegram.org/bot" ascii wide
        $exfil_2 = "discord.com/api/webhooks" ascii wide
        $exfil_3 = "discordapp.com/api/webhooks" ascii wide
        $upload_1 = "multipart/form-data" ascii wide
        $upload_2 = "UploadFile" ascii
        $upload_3 = "sendDocument" ascii wide
        $crypto_1 = "CryptUnprotectData" ascii
        $crypto_2 = "ProtectedData" ascii
        $crypto_3 = "BCryptDecrypt" ascii
    condition:
        General_WinPE_AnySizePE and $credential and $key and ($cookie or $nss) and
        2 of ($target_*) and 1 of ($exfil_*) and 1 of ($upload_*) and 1 of ($crypto_*) and
        (pe.data_directories[14].size > 0 or pe.imports("kernel32.dll", "GetProcAddress"))
}

rule TrojanSpy_MSIL_VaultKeylogger
{
    meta:
        description = "Managed credential-vault access, global keyboard capture and SMTP reporting cluster"
        author = "PYAS Security"
        date = "2026-09-14"
        scope = "managed Windows PE assemblies; capability-level heuristic"
        evidence = "compound condition requires managed PE structure, vault APIs, keyboard-hook APIs, SMTP, screen-capture and decryption signals"
        attribution = "capability cluster; not a verified family name"
    strings:
        $vault_1 = "VaultEnumerateItems" ascii fullword
        $vault_2 = "VaultOpenVault" ascii fullword
        $vault_3 = "VaultGetItem" ascii fullword
        $vault_4 = "VaultFree" ascii fullword
        $key_1 = "SetWindowsHookEx" ascii fullword
        $key_2 = "CallNextHookEx" ascii fullword
        $key_3 = "ToUnicodeEx" ascii fullword
        $key_4 = "GetForegroundWindow" ascii fullword
        $send_1 = "SmtpClient" ascii fullword
        $send_2 = "MailMessage" ascii fullword
        $capture = "CopyFromScreen" ascii fullword
        $decrypt = "Unprotect" ascii fullword
    condition:
        General_WinPE_AnySizePE and pe.data_directories[14].size > 0 and
        all of ($vault_*) and 3 of ($key_*) and all of ($send_*) and $capture and $decrypt and
        for any s in (0..pe.number_of_sections-1) : (
            (pe.sections[s].characteristics & pe.SECTION_MEM_EXECUTE) != 0 and
            $vault_1 in (pe.sections[s].raw_data_offset..pe.sections[s].raw_data_offset+pe.sections[s].raw_data_size-1) and
            $key_1 in (pe.sections[s].raw_data_offset..pe.sections[s].raw_data_offset+pe.sections[s].raw_data_size-1)
        )
}

rule TEST_WinPE_NOTAVIRUS 
{
   meta:
      description = "PYAS Security Verification Test Rules"
      author = "PYAS Security"
      date = "2026-07-02"
      scope = "internal scanner verification artifacts only; not a malware detection"
      evidence = "compound condition requires internal seven-of-eight marker match gated on an MZ file larger than 20 MB"
      attribution = "internal verification marker; malware-family attribution not applicable"
   strings:
      $s1 = "VUZsQlUxO" wide
      $s2 = "VRaV04xY21s" wide
      $s3 = "MGVW" wide
      $s4 = "OUJkWFJvYjNKc" wide
      $s5 = "GVtRjBhVz" wide
      $s6 = "l1WDFabGNtbG" ascii
      $s7 = "1hV05o" fullword ascii
      $s8 = "ZEdsdmJnPT0=" ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 20MB and
      7 of them
}
