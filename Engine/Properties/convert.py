import os, sys, time, ctypes, sqlite3, datetime, pefile, math
import numpy as np
import ctypes.wintypes

####################################################################################################

DB_PATH = "pe_features.db"
BATCH_SIZE = 100 
MAX_FILE_SIZE = 256 * 1024 * 1024 
TARGET_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.ocx', '.scr', '.efi', '.acm', '.ax', '.cpl', '.drv', '.com'
}

####################################################################################################

class Features:
    SCHEMA = [
        "FileEntropy", "IsExe", "IsDll", "IsDriver", "Is64Bit", "Machine", "Magic",
        "TimeDateStamp", "CheckSum", "ImageBase", "SizeOfImage", "SizeOfHeaders",
        "Characteristics", "DllCharacteristics", "Subsystem", "LoaderFlags",
        "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode", 
        "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint",
        "BaseOfCode", "SectionAlignment", "FileAlignment",
        "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
        "MajorImageVersion", "MinorImageVersion",
        "MajorSubsystemVersion", "MinorSubsystemVersion",
        "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit",
        "NumberOfSections", "NumberOfRvaAndSizes", "PointerToSymbolTable", "NumberOfSymbols",
        "SizeOfOptionalHeader",
        
        "TextSection", "TextSizeRatio", "DataSection", "DataSizeRatio", 
        "RsrcSection", "RsrcSizeRatio", "SectionCount", "ExecutableSections", 
        "WritableSections", "ReadableSections", "SectionException",
        "IconCount", "ApiCount", "ExportCount", "DebugCount", "ExceptionCount",
        "FileDescriptionLength", "FileVersionLength", "ProductNameLength", 
        "ProductVersionLength", "CompanyNameLength", "LegalCopyrightLength", 
        "CommentsLength", "InternalNameLength", "LegalTrademarksLength",
        "SpecialBuildLength", "PrivateBuildLength",
        
        "TrustSigned", "IsDebug", "IsPatched", "IsPrivateBuild", "IsPreRelease", 
        "IsSpecialBuild", "IsAdmin", "IsInstall", "HasTlsCallbacks", 
        "HasInvalidTimestamp", "HasRelocationDirectory", "HasPacked", "FileTimeException",
        
        "_CorExeMain", "_CorDllMain",
        
        "GetDC", "CreateDCW", "CreateDCA", "BitBlt", "StretchBlt", "CreateCompatibleDC",
        "CreateCompatibleBitmap", "SelectObject", "DeleteDC", "DeleteObject", "GetDeviceCaps",
        "GetSystemMetrics",
        
        "SetWindowsHookExA", "SetWindowsHookExW", "UnhookWindowsHookEx", 
        "GetAsyncKeyState", "GetKeyState", "GetKeyboardState", 
        "MapVirtualKeyA", "MapVirtualKeyW", "MapVirtualKeyExA", "MapVirtualKeyExW", 
        "ToAscii", "ToAsciiEx", "ToUnicode", "ToUnicodeEx", "KeybdEvent", "SendInput",
        
        "GetCursorPos", "SetCursorPos", "MouseEvent", "GetDoubleClickTime", 
        "GetCapture", "SetCapture",
        
        "WaveInOpen", "WaveInClose", "WaveInStart", "WaveInStop", 
        "CapCreateCaptureWindowA", "CapCreateCaptureWindowW", 
        "OpenClipboard", "CloseClipboard", "GetClipboardData", "SetClipboardData",
        
        "GetDesktopWindow", "GetForegroundWindow", "GetWindowDC", "GetWindowRect",
        "GetClientRect", "PrintWindow", "SetWindowDisplayAffinity", "FindWindowA", "FindWindowW",
        "EnumWindows", "EnumChildWindows",
        
        "Direct3DCreate9", "D3D11CreateDevice", "GdipSaveImageToFile",
        
        "CreateProcessA", "CreateProcessW", "CreateThread", "ResumeThread", "SuspendThread",
        "OpenProcess", "TerminateProcess", "GetCurrentProcess", "GetCurrentProcessId",
        "ExitProcess", "WinExec", "ShellExecuteA", "ShellExecuteW",
        
        "CreateRemoteThread", "QueueUserAPC", "VirtualAlloc", "VirtualAllocEx",
        "VirtualProtect", "VirtualProtectEx", "WriteProcessMemory", "ReadProcessMemory",
        "NtUnmapViewOfSection", "SetThreadContext", "GetThreadContext", "Wow64SetThreadContext",
        "ZwUnmapViewOfSection", "CreateFileMappingA", "CreateFileMappingW", "MapViewOfFile",
        "UnmapViewOfSection",
        
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", 
        "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW", "FreeLibrary",
        
        "CreateFileA", "CreateFileW", "WriteFile", "ReadFile", "DeleteFileA", "DeleteFileW",
        "CopyFileA", "CopyFileW", "MoveFileA", "MoveFileW", "FindFirstFileA", "FindNextFileA",
        "GetTempPathA", "GetTempPathW", "GetTempFileNameA", "GetTempFileNameW", 
        "SetFileAttributesA", "SetFileAttributesW", "DeviceIoControl", "SetFileTime",
        
        "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW", 
        "RegCreateKeyExA", "RegCreateKeyExW", "RegDeleteKeyA", "RegDeleteKeyW",
        "RegEnumValueA", "RegEnumValueW", "RegQueryValueExA", "RegQueryValueExW",
        "RegDeleteValueA", "RegDeleteValueW",
        
        "OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW",
        "StartServiceA", "StartServiceW", "ControlService", "DeleteService",
        
        "AdjustTokenPrivileges", "LookupPrivilegeValueA", "LookupPrivilegeValueW", 
        "OpenProcessToken", "NetUserAdd", "NetLocalGroupAddMembers",
        
        "Socket", "Connect", "Send", "Recv", "WSAStartup", "gethostbyname", "getaddrinfo",
        "WSAIoctl", "WSASocketA", "WSASocketW",
        "URLDownloadToFileA", "URLDownloadToFileW", 
        "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
        "InternetOpenUrlA", "InternetOpenUrlW",
        "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
        "InternetReadFile", "DnsQuery_A", "DnsQuery_W",
        
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA", "OutputDebugStringW",
        "GetTickCount", "QueryPerformanceCounter", "Sleep", "GetSystemTimeAsFileTime",
        "GetLocalTime", "GlobalMemoryStatus", "GetVersionExA", "GetVersionExW",
        "GetComputerNameA", "GetComputerNameW", "GetUserNameA", "GetUserNameW",
        
        "CryptAcquireContextA", "CryptAcquireContextW", "CryptCreateHash", "CryptHashData", 
        "CryptDeriveKey", "CryptEncrypt", "CryptDecrypt", "CryptDestroyKey", "CryptDestroyHash",
        "CryptReleaseContext", "CryptGenKey", "CryptImportKey", "CryptExportKey",
        "RtlDecompressBuffer", "ConnectNamedPipe", "PeekNamedPipe"
    ]
    
    SCHEMA_SET = set(SCHEMA)
    PACKERS = {
        'upx', 'aspack', 'asprotect', 'pecompact', 'upack', 'fsg', 'mew', 
        'mpress', 'ezip', 'pklt', 'shrink', 'petite', 'telock',
        
        'themida', 'winlicense', 'tmd', 'vmp', 'enigma', 'obsidium', 
        'pelock', 'exestealth', 'yoda', 'armadillo', 'zprotect',
        'sforce', 'starforce', 'qihoo', 'wisevec', 'megastop',
    }
    INSTALLER_SIGS = [b"Nullsoft.NSIS", b"Inno Setup", b"7-Zip.7zip", b"InstallShield"]

####################################################################################################

def verify_signature(file_path):
    if os.name != 'nt':
        return 0
    try:
        wintrust = ctypes.windll.wintrust
        WINTRUST_ACTION_GENERIC_VERIFY_V2 = ctypes.c_char_p(b'\x6b\xc5\xaa\x00\x44\xcd\xd0\x11\x8c\xc2\x00\xc0\x4f\xc2\x95\xee')

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct", ctypes.wintypes.DWORD),
                ("pcwszFilePath", ctypes.wintypes.LPCWSTR),
                ("hFile", ctypes.wintypes.HANDLE),
                ("pgKnownSubject", ctypes.wintypes.LPVOID)
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct", ctypes.wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.wintypes.LPVOID),
                ("pSIPClientData", ctypes.wintypes.LPVOID),
                ("dwUIChoice", ctypes.wintypes.DWORD),
                ("fdwRevocationChecks", ctypes.wintypes.DWORD),
                ("dwUnionChoice", ctypes.wintypes.DWORD),
                ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                ("dwStateAction", ctypes.wintypes.DWORD),
                ("hWVTStateData", ctypes.wintypes.HANDLE),
                ("pwszURLReference", ctypes.wintypes.LPCWSTR),
                ("dwProvFlags", ctypes.wintypes.DWORD),
                ("dwUIContext", ctypes.wintypes.DWORD),
                ("pSignatureSettings", ctypes.wintypes.LPVOID)
            ]

        fi = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), file_path, None, None)
        td = WINTRUST_DATA(ctypes.sizeof(WINTRUST_DATA), None, None, 2, 1, 1, ctypes.pointer(fi), 0, None, None, 0x00000080, 0, None)
        action = ctypes.wintypes.GUID.from_buffer_copy(WINTRUST_ACTION_GENERIC_VERIFY_V2)
        return 1 if wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(td)) == 0 else 0
    except:
        return 0

####################################################################################################

def safe_float(val):
    try:
        f = float(val)
        if math.isinf(f) or math.isnan(f):
            return 0.0
        return f
    except:
        return 0.0

def process_single_file(file_path):
    def _calc_entropy(data):
        if not data:
            return 0.0
        arr = np.frombuffer(data, dtype=np.uint8)
        counts = np.bincount(arr, minlength=256)
        probs = counts[counts > 0] / len(arr)
        return float(-np.sum(probs * np.log2(probs)))

    def _safe_div(n, d):
        return n / d if d > 0 else 0.0

    try:
        fsize = os.path.getsize(file_path)
        if fsize == 0 or fsize > MAX_FILE_SIZE:
            return None
    except:
        return None

    fts = {k: 0 for k in Features.SCHEMA}
    pe = None
    try:
        pe = pefile.PE(file_path, fast_load=True)
        
        fts['TrustSigned'] = verify_signature(file_path)

        fh = pe.FILE_HEADER
        fts['Machine'] = fh.Machine
        fts['NumberOfSections'] = fh.NumberOfSections
        fts['TimeDateStamp'] = fh.TimeDateStamp
        fts['PointerToSymbolTable'] = fh.PointerToSymbolTable
        fts['NumberOfSymbols'] = fh.NumberOfSymbols
        fts['SizeOfOptionalHeader'] = fh.SizeOfOptionalHeader
        fts['Characteristics'] = fh.Characteristics

        curr_ts = datetime.datetime.utcnow().timestamp()
        fts['HasInvalidTimestamp'] = 1 if (fh.TimeDateStamp < 631152000 or fh.TimeDateStamp > curr_ts + 2592000) else 0

        if hasattr(pe, 'OPTIONAL_HEADER'):
            op = pe.OPTIONAL_HEADER
            fts['Magic'] = op.Magic
            fts['MajorLinkerVersion'] = op.MajorLinkerVersion
            fts['MinorLinkerVersion'] = op.MinorLinkerVersion
            fts['SizeOfCode'] = op.SizeOfCode
            fts['SizeOfInitializedData'] = op.SizeOfInitializedData
            fts['SizeOfUninitializedData'] = op.SizeOfUninitializedData
            fts['AddressOfEntryPoint'] = op.AddressOfEntryPoint
            fts['BaseOfCode'] = op.BaseOfCode
            fts['ImageBase'] = op.ImageBase
            fts['SectionAlignment'] = op.SectionAlignment
            fts['FileAlignment'] = op.FileAlignment
            fts['MajorOperatingSystemVersion'] = op.MajorOperatingSystemVersion
            fts['MinorOperatingSystemVersion'] = op.MinorOperatingSystemVersion
            fts['MajorImageVersion'] = op.MajorImageVersion
            fts['MinorImageVersion'] = op.MinorImageVersion
            fts['MajorSubsystemVersion'] = op.MajorSubsystemVersion
            fts['MinorSubsystemVersion'] = op.MinorSubsystemVersion
            fts['SizeOfImage'] = op.SizeOfImage
            fts['SizeOfHeaders'] = op.SizeOfHeaders
            fts['CheckSum'] = op.CheckSum
            fts['Subsystem'] = op.Subsystem
            fts['DllCharacteristics'] = op.DllCharacteristics
            fts['SizeOfStackReserve'] = op.SizeOfStackReserve
            fts['SizeOfStackCommit'] = op.SizeOfStackCommit
            fts['SizeOfHeapReserve'] = op.SizeOfHeapReserve
            fts['SizeOfHeapCommit'] = op.SizeOfHeapCommit
            fts['LoaderFlags'] = op.LoaderFlags
            fts['NumberOfRvaAndSizes'] = op.NumberOfRvaAndSizes

            fts['Is64Bit'] = 1 if fh.Machine == 0x8664 else 0
            fts['IsExe'] = 1 if pe.is_exe() else 0
            fts['IsDll'] = 1 if pe.is_dll() else 0
            fts['IsDriver'] = 1 if pe.is_driver() else 0

            if len(op.DATA_DIRECTORY) > 9 and op.DATA_DIRECTORY[9].VirtualAddress > 0:
                fts['HasTlsCallbacks'] = 1
            if len(op.DATA_DIRECTORY) > 5 and op.DATA_DIRECTORY[5].Size > 0:
                fts['HasRelocationDirectory'] = 1

        pe.parse_sections(pe.FILE_HEADER.NumberOfSections)
        
        file_data = pe.get_memory_mapped_image()
        fts['FileEntropy'] = _calc_entropy(file_data)

        fts['SectionCount'] = len(pe.sections)
        for section in pe.sections:
            try:
                name = section.Name.decode('ascii', 'ignore').strip('\x00')
            except:
                name = ""
            s_data = section.get_data()
            s_entropy = _calc_entropy(s_data)

            if any(p in name.lower() for p in Features.PACKERS):
                fts['HasPacked'] = 1
            if section.Characteristics & 0x20000000:
                fts['ExecutableSections'] += 1
            if section.Characteristics & 0x80000000:
                fts['WritableSections'] += 1
            if section.Characteristics & 0x40000000:
                fts['ReadableSections'] += 1
            if section.SizeOfRawData + section.PointerToRawData > fsize:
                fts['SectionException'] = 1

            ratio = _safe_div(section.SizeOfRawData, fsize)
            if name.startswith('.text'):
                fts['TextSection'] = s_entropy
                fts['TextSizeRatio'] = ratio
            elif name.startswith('.data'):
                fts['DataSection'] = s_entropy
                fts['DataSizeRatio'] = ratio
            elif name.startswith('.rsrc'):
                fts['RsrcSection'] = s_entropy
                fts['RsrcSizeRatio'] = ratio
                if b"requireAdministrator" in s_data:
                    fts['IsAdmin'] = 1

                for sig in Features.INSTALLER_SIGS:
                    if sig in s_data:
                        fts['IsInstall'] = 1
                        break

        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']
        ])

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    fts['ApiCount'] += 1
                    if not imp or not hasattr(imp, 'name') or not imp.name:
                        continue
                    try:
                        name = imp.name.decode('ascii', 'ignore')
                        if name in Features.SCHEMA_SET:
                            fts[name] = 1
                    except:
                        pass

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            fts['ExportCount'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if entry.id == 3 and hasattr(entry, 'directory'):
                    fts['IconCount'] = len(entry.directory.entries)
                    break
        
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            fts['DebugCount'] = len(pe.DIRECTORY_ENTRY_DEBUG)

        for k in fts:
            fts[k] = safe_float(fts[k])

        return fts

    except Exception:
        return None
    finally:
        if pe:
            pe.close()

####################################################################################################

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA synchronous = OFF")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA cache_size = 10000")
    cols = ", ".join([f"{c} REAL" for c in Features.SCHEMA])
    conn.execute(f"CREATE TABLE IF NOT EXISTS PeData ({cols}, Label INTEGER)")
    conn.commit()
    return conn

def prune_db_duplicates(conn):
    try:
        print("\n[*] Post-processing: Checking for and removing duplicate entries...")
        all_cols = ", ".join(Features.SCHEMA + ["Label"])
        
        sql_count_before = "SELECT COUNT(*) FROM PeData"
        before = conn.execute(sql_count_before).fetchone()[0]
        
        sql_dedup = f"""
            DELETE FROM PeData 
            WHERE rowid NOT IN (
                SELECT MIN(rowid) 
                FROM PeData 
                GROUP BY {all_cols}
            )
        """
        conn.execute(sql_dedup)
        conn.commit()
        
        after = conn.execute(sql_count_before).fetchone()[0]
        removed = before - after
        
        if removed > 0:
            print(f"[+] Deduplication complete. Removed {removed} duplicate rows.")
            print("    (Duplicates occur if the same file is scanned multiple times)")
        else:
            print("[+] Deduplication complete. No duplicates found.")
            
    except Exception as e:
        print(f"[-] Deduplication Warning: {e}")

####################################################################################################

def scan_and_save(conn, path, label):
    print(f"\n[*] Scanning: {path} (Label={label})")
    print(f"[*] Config: Max File Size = {MAX_FILE_SIZE/1024/1024:.0f} MB")
    
    files = []
    print("[*] Walking directory tree...")
    if os.path.isfile(path): 
        files.append(path)
    else:
        for r, _, fs in os.walk(path):
            for f in fs:
                if os.path.splitext(f)[1].lower() in TARGET_EXTENSIONS:
                    files.append(os.path.join(r, f))
    
    total = len(files)
    if total == 0:
        print("[-] No valid PE files found in this path.")
        return

    print(f"[*] Found {total} files. Processing...")
    
    batch = []
    count = 0
    errors = 0
    start_time = time.time()
    
    placeholders = ",".join(["?"] * (len(Features.SCHEMA) + 1))
    sql = f"INSERT INTO PeData VALUES ({placeholders})"
    
    try:
        for i, file_path in enumerate(files):
            res = process_single_file(file_path)
            
            if res:
                vals = [res.get(c, 0.0) for c in Features.SCHEMA]
                vals.append(float(label))
                batch.append(tuple(vals))
                count += 1
            else:
                errors += 1
            
            if len(batch) >= BATCH_SIZE:
                try:
                    conn.executemany(sql, batch)
                    conn.commit()
                    batch = []
                except Exception as batch_err:
                    print(f"\n[-] Batch Error: {batch_err}. Retrying strictly...")
                    for row in batch:
                        try:
                            conn.execute(sql, row)
                        except Exception:
                            errors += 1
                            count -= 1 
                    conn.commit()
                    batch = []
            
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            sys.stdout.write(f"\r[{i+1}/{total}] OK: {count} | Skip/Err: {errors} | {rate:.1f} files/s")
            sys.stdout.flush()

    except KeyboardInterrupt:
        print("\n\n[-] Interrupted by user.")
    except Exception as e:
        print(f"\n[-] Unexpected Error: {e}")
    finally:
        if batch:
            print(f"\n[*] Saving remaining {len(batch)} items...")
            try:
                conn.executemany(sql, batch)
                conn.commit()
            except Exception as final_err:
                print(f"[-] Final Batch Error: {final_err}. Retrying strictly...")
                for row in batch:
                    try:
                        conn.execute(sql, row)
                    except Exception:
                        pass
                conn.commit()
        
        print(f"\n[+] Scan finished/stopped. Total added: {count}")
        prune_db_duplicates(conn)

####################################################################################################

if __name__ == "__main__":
    print("\n---------------- PE Dataset Builder v2.6 ----------------\n")
    print("Type 'exit' or 'q' at any prompt to quit.")
    
    if os.path.exists(DB_PATH):
        print(f"[-] Note: If SCHEMA changed, please delete {DB_PATH} before running.")

    conn = init_db()
    try:
        while True:
            print("\n---------------------------------------------------------\n")
            raw_path = input("[*] Enter Path (File or Folder): ").strip()
            target_path = raw_path.strip('"').strip("'")

            if target_path.lower() in ['exit', 'q']:
                break

            if not target_path or not os.path.exists(target_path):
                print("[-] Invalid path. Please try again.")
                continue

            while True:
                label_input = input("[*] Enter Label (0=Safe, 1=Malware): ").strip()
                if label_input.lower() in ['exit', 'q']:
                    conn.close()
                    sys.exit()

                if label_input in ['0', '1']:
                    label = int(label_input)
                    break
                else:
                    print("[-] Please enter 0 or 1.")

            scan_and_save(conn, target_path, label)
    except KeyboardInterrupt:
        print("\n\n[-] Interrupted.")
    finally:
        conn.close()
        print(f"\n[+] Database saved to: {os.path.abspath(DB_PATH)}")
