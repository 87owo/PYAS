import os, sys, math, time, datetime, pefile, hashlib
import ctypes, ctypes.wintypes, multiprocessing

try:
    import orjson
    JSON_DUMPS = lambda x: orjson.dumps(x).decode('utf-8')
    JSON_LOADS = orjson.loads
    HAS_ORJSON = True
except ImportError:
    import json
    JSON_DUMPS = json.dumps
    JSON_LOADS = json.loads
    HAS_ORJSON = False

####################################################################################################

JSONL_PATH = "pe_features.jsonl"
BATCH_SIZE = 1000
MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024
MAX_WORKERS = os.cpu_count() - 2

####################################################################################################

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pcwszFilePath", ctypes.wintypes.LPCWSTR),
        ("hFile", ctypes.wintypes.HANDLE),
        ("pgKnownSubject", ctypes.wintypes.LPVOID)
    ]

class WINTRUST_DATA_UNION(ctypes.Union):
    _fields_ = [
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("pCatalog", ctypes.wintypes.LPVOID),
        ("pBlob", ctypes.wintypes.LPVOID),
        ("pSgnr", ctypes.wintypes.LPVOID),
        ("pCert", ctypes.wintypes.LPVOID)
    ]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.wintypes.LPVOID),
        ("pSIPClientData", ctypes.wintypes.LPVOID),
        ("dwUIChoice", ctypes.wintypes.DWORD),
        ("fdwRevocationChecks", ctypes.wintypes.DWORD),
        ("dwUnionChoice", ctypes.wintypes.DWORD),
        ("u", WINTRUST_DATA_UNION),
        ("dwStateAction", ctypes.wintypes.DWORD),
        ("hWVTStateData", ctypes.wintypes.HANDLE),
        ("pwszURLReference", ctypes.wintypes.LPCWSTR),
        ("dwProvFlags", ctypes.wintypes.DWORD),
        ("dwUIContext", ctypes.wintypes.DWORD),
        ("pSignatureSettings", ctypes.wintypes.LPVOID)
    ]

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.wintypes.DWORD),
        ("Data2", ctypes.wintypes.WORD),
        ("Data3", ctypes.wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8)
    ]

V2_GUID = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

####################################################################################################

def verify_signature(file_path):
    if os.name != 'nt': return 0
    try:
        wintrust = ctypes.windll.wintrust
        wintrust.WinVerifyTrust.argtypes = [ctypes.wintypes.HWND, ctypes.POINTER(GUID), ctypes.wintypes.LPVOID]
        wintrust.WinVerifyTrust.restype = ctypes.wintypes.LONG
        
        abs_path = os.path.abspath(file_path)
        
        fi = WINTRUST_FILE_INFO()
        fi.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        fi.pcwszFilePath = abs_path
        fi.hFile = None
        fi.pgKnownSubject = None
        
        wt_union = WINTRUST_DATA_UNION()
        wt_union.pFile = ctypes.pointer(fi)
        
        td = WINTRUST_DATA()
        td.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        td.pPolicyCallbackData = None
        td.pSIPClientData = None
        td.dwUIChoice = 2
        td.fdwRevocationChecks = 0
        td.dwUnionChoice = 1
        td.u = wt_union
        td.dwStateAction = 0
        td.hWVTStateData = None
        td.pwszURLReference = None
        td.dwProvFlags = 0
        td.dwUIContext = 0
        td.pSignatureSettings = None

        return 1 if wintrust.WinVerifyTrust(None, ctypes.byref(V2_GUID), ctypes.byref(td)) == 0 else 0
    except Exception:
        return 0

####################################################################################################

class FeatureExtractor:
    @staticmethod
    def _safe_float(val):
        try:
            f = float(val)
            return f if not (math.isinf(f) or math.isnan(f)) else 0.0
        except Exception: 
            return 0.0

    @staticmethod
    def _calc_entropy(data):
        if not data: return 0.0
        import numpy as np
        arr = np.frombuffer(data, dtype=np.uint8)
        counts = np.bincount(arr, minlength=256)
        probs = counts[counts > 0] / len(arr)
        return float(-np.sum(probs * np.log2(probs)))

    @classmethod
    def _extract_overlay_features(cls, pe, fsize):
        overlay_offset = pe.get_overlay_data_start_offset()
        if not overlay_offset or overlay_offset >= fsize:
            return {"HasOverlay": 0.0, "OverlaySize": 0.0, "OverlayRatio": 0.0, "OverlayEntropy": 0.0}
        
        overlay_data = pe.get_overlay()
        if not overlay_data:
            return {"HasOverlay": 0.0, "OverlaySize": 0.0, "OverlayRatio": 0.0, "OverlayEntropy": 0.0}

        sz = len(overlay_data)
        return {
            "HasOverlay": 1.0,
            "OverlaySize": float(sz),
            "OverlayRatio": float(sz) / float(fsize),
            "OverlayEntropy": cls._calc_entropy(overlay_data)
        }

    @classmethod
    def _extract_rich_header(cls, pe):
        if not hasattr(pe, 'RICH_HEADER') or not pe.RICH_HEADER:
            return {"HasRichHeader": 0.0, "RichHeaderCount": 0.0}
        return {
            "HasRichHeader": 1.0,
            "RichHeaderCount": float(len(pe.RICH_HEADER.values) // 2) if hasattr(pe.RICH_HEADER, 'values') else 0.0
        }

    @classmethod
    def _extract_ep_anomalies(cls, pe):
        if not hasattr(pe, 'OPTIONAL_HEADER') or not hasattr(pe, 'sections') or not pe.sections:
            return {"EntryPointSectionIndex": -1.0, "EntryPointInExecutable": 0.0, "EntryPointInLastSection": 0.0}

        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_section_idx = -1
        ep_in_exec = 0.0
        
        for idx, sec in enumerate(pe.sections):
            if sec.VirtualAddress <= ep < (sec.VirtualAddress + sec.Misc_VirtualSize):
                ep_section_idx = idx
                if sec.Characteristics & 0x20000000:
                    ep_in_exec = 1.0
                break
                
        return {
            "EntryPointSectionIndex": float(ep_section_idx),
            "EntryPointInExecutable": ep_in_exec,
            "EntryPointInLastSection": 1.0 if ep_section_idx == len(pe.sections) - 1 else 0.0
        }

    @classmethod
    def _extract_advanced_resources(cls, pe):
        res_data = {
            "ResourceMaxEntropy": 0.0,
            "ResourceMinEntropy": 0.0,
            "ResourceMeanEntropy": 0.0,
            "ResourceLangCount": 0.0,
            "ResourceRCDataCount": 0.0
        }
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return res_data
            
        entropies = []
        langs = set()
        rcdata_count = 0
        
        for entry_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(entry_type, 'id') and entry_type.id == 10: 
                rcdata_count += len(getattr(entry_type.directory, 'entries', []))
                
            if not hasattr(entry_type, 'directory'):
                continue
                
            for entry_id in entry_type.directory.entries:
                if not hasattr(entry_id, 'directory'):
                    continue
                    
                for entry_lang in entry_id.directory.entries:
                    if hasattr(entry_lang, 'id'):
                        langs.add(entry_lang.id)
                    if hasattr(entry_lang, 'data'):
                        try:
                            data = pe.get_data(entry_lang.data.struct.OffsetToData, entry_lang.data.struct.Size)
                            entropies.append(cls._calc_entropy(data))
                        except Exception:
                            continue
                            
        res_data["ResourceLangCount"] = float(len(langs))
        res_data["ResourceRCDataCount"] = float(rcdata_count)
        
        if entropies:
            res_data["ResourceMaxEntropy"] = max(entropies)
            res_data["ResourceMinEntropy"] = min(entropies)
            res_data["ResourceMeanEntropy"] = sum(entropies) / len(entropies)
            
        return res_data

    @classmethod
    def _extract_load_config(cls, pe):
        cfg = {"HasLoadConfig": 0.0, "HasCFG": 0.0, "HasSEHTable": 0.0}
        if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
            cfg["HasLoadConfig"] = 1.0
            struct = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
            if getattr(struct, 'GuardCFFunctionTable', 0) != 0:
                cfg["HasCFG"] = 1.0
            if getattr(struct, 'SEHandlerTable', 0) != 0:
                cfg["HasSEHTable"] = 1.0
        return cfg

    @classmethod
    def _extract_security_directory(cls, pe, file_bytes, fsize):
        res = {"HasSignature": 0.0, "SignatureCount": 0.0}
        if not hasattr(pe, 'OPTIONAL_HEADER') or not hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
            return res

        sec_idx = 4
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directories) <= sec_idx:
            return res

        sec_dir = directories[sec_idx]
        if sec_dir.Size == 0 or sec_dir.VirtualAddress == 0:
            return res

        res["HasSignature"] = 1.0
        offset = sec_dir.VirtualAddress
        size = sec_dir.Size

        if offset + size > fsize or offset < 0 or size < 0:
            return res

        count = 0
        curr = offset
        end = offset + size

        while curr + 8 <= end:
            dw_length = int.from_bytes(file_bytes[curr:curr+4], 'little')
            if dw_length < 8:
                break
            count += 1
            curr += (dw_length + 7) & ~7

        res["SignatureCount"] = float(count)
        return res

    @classmethod
    def extract(cls, file_bytes, file_path, fsize):
        if fsize == 0: return None
        base, dlls, apis, pe = {}, set(), set(), None

        try:
            pe = pefile.PE(data=file_bytes, fast_load=True)
            
            try:
                pe.parse_rich_header()
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'], 
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'], 
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'], 
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'], 
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']
                ])
            except Exception: 
                pass
            
            base['TrustSigned'] = verify_signature(file_path)
            base['FileEntropy'] = cls._calc_entropy(file_bytes)
            base['FileSize'] = fsize
            
            fh = pe.FILE_HEADER
            base['Machine'] = getattr(fh, 'Machine', 0)
            base['NumberOfSections'] = getattr(fh, 'NumberOfSections', 0)
            base['TimeDateStamp'] = getattr(fh, 'TimeDateStamp', 0)
            base['PointerToSymbolTable'] = getattr(fh, 'PointerToSymbolTable', 0)
            base['NumberOfSymbols'] = getattr(fh, 'NumberOfSymbols', 0)
            base['SizeOfOptionalHeader'] = getattr(fh, 'SizeOfOptionalHeader', 0)
            base['Characteristics'] = getattr(fh, 'Characteristics', 0)

            curr_ts = datetime.datetime.utcnow().timestamp()
            base['HasInvalidTimestamp'] = 1.0 if (base['TimeDateStamp'] < 631152000 or base['TimeDateStamp'] > curr_ts + 2592000) else 0.0
            base['FileTimeException'] = 1.0 if base['TimeDateStamp'] == 0 else 0.0
            base['Is64Bit'] = 1.0 if base['Machine'] in (0x8664, 0xAA64, 0x0200) else 0.0
            base['IsExe'] = 1.0 if pe.is_exe() else 0.0
            base['IsDll'] = 1.0 if pe.is_dll() else 0.0

            base['ExceptionCount'] = 0.0

            if hasattr(pe, 'OPTIONAL_HEADER'):
                op = pe.OPTIONAL_HEADER
                fields = ['Magic', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode', 'ImageBase', 'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes']
                for f in fields: base[f] = getattr(op, f, 0)
                base['IsDriver'] = 1.0 if base.get('Subsystem') == 1 else 0.0

                if hasattr(op, 'DATA_DIRECTORY'):
                    for i, directory in enumerate(op.DATA_DIRECTORY):
                        base[f'DataDirectory_{i}_Size'] = directory.Size
                        base[f'DataDirectory_{i}_VA'] = directory.VirtualAddress
                    
                    exc_idx = pefile.DIRECTORY_ENTRY.get('IMAGE_DIRECTORY_ENTRY_EXCEPTION', 3)
                    if len(op.DATA_DIRECTORY) > exc_idx and op.DATA_DIRECTORY[exc_idx].Size > 0:
                        base['ExceptionCount'] = op.DATA_DIRECTORY[exc_idx].Size // 12 if base['Machine'] in (0x8664, 0xAA64) else 0.0

            char_flags = [0x00000020, 0x00000040, 0x00000080, 0x02000000, 0x20000000, 0x40000000, 0x80000000]
            for flag in char_flags:
                base[f'Char_{flag:08X}_Count'] = 0.0
                base[f'Char_{flag:08X}_MeanEntropy'] = 0.0

            if hasattr(pe, 'sections'):
                base['SectionCount'] = len(pe.sections)
                entropies, raw_sizes, v_sizes = [], [], []
                exec_sec, write_sec, read_sec, sec_exc = 0, 0, 0, 0
                
                for section in pe.sections:
                    try:
                        s_data = section.get_data()
                        s_entropy = cls._calc_entropy(s_data)
                    except Exception: 
                        s_entropy = 0.0

                    entropies.append(s_entropy)
                    raw_sizes.append(section.SizeOfRawData)
                    v_sizes.append(section.Misc_VirtualSize)

                    if section.Characteristics & 0x20000000: exec_sec += 1
                    if section.Characteristics & 0x80000000: write_sec += 1
                    if section.Characteristics & 0x40000000: read_sec += 1
                    if section.SizeOfRawData + section.PointerToRawData > fsize: sec_exc = 1

                    for flag in char_flags:
                        if section.Characteristics & flag:
                            base[f'Char_{flag:08X}_Count'] += 1.0
                            base[f'Char_{flag:08X}_MeanEntropy'] += s_entropy

                base['SectionMaxEntropy'] = max(entropies) if entropies else 0.0
                base['SectionMinEntropy'] = min(entropies) if entropies else 0.0
                base['SectionMeanEntropy'] = sum(entropies) / len(entropies) if entropies else 0.0
                base['SectionMaxRawSize'] = max(raw_sizes) if raw_sizes else 0.0
                base['SectionMinRawSize'] = min(raw_sizes) if raw_sizes else 0.0
                base['SectionMeanRawSize'] = sum(raw_sizes) / len(raw_sizes) if raw_sizes else 0.0
                base['SectionMaxVSize'] = max(v_sizes) if v_sizes else 0.0
                base['SectionMinVSize'] = min(v_sizes) if v_sizes else 0.0
                base['SectionMeanVSize'] = sum(v_sizes) / len(v_sizes) if v_sizes else 0.0
                base['ExecutableSections'] = exec_sec
                base['WritableSections'] = write_sec
                base['ReadableSections'] = read_sec
                base['SectionException'] = float(sec_exc)

                for flag in char_flags:
                    if base[f'Char_{flag:08X}_Count'] > 0:
                        base[f'Char_{flag:08X}_MeanEntropy'] = base[f'Char_{flag:08X}_MeanEntropy'] / base[f'Char_{flag:08X}_Count']

            string_keys = ['FileDescription', 'FileVersion', 'ProductName', 'ProductVersion', 'CompanyName', 'LegalCopyright', 'Comments', 'InternalName', 'LegalTrademarks', 'SpecialBuild', 'PrivateBuild']
            for key in string_keys: 
                base[f'{key}Length'] = 0.0
                
            if hasattr(pe, 'FileInfo'):
                for fileinfo_list in pe.FileInfo:
                    for fileinfo in fileinfo_list:
                        if getattr(fileinfo, 'name', '') in ('StringFileInfo', b'StringFileInfo'):
                            for st in getattr(fileinfo, 'StringTable', []):
                                for key, val in st.entries.items():
                                    try:
                                        k = key.decode('utf-8', 'ignore') if isinstance(key, bytes) else str(key)
                                        if k in string_keys:
                                            v = val.decode('utf-8', 'ignore') if isinstance(val, bytes) else str(val)
                                            base[f'{k}Length'] = float(len(v))
                                    except Exception: 
                                        continue

            if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and hasattr(pe.DIRECTORY_ENTRY_TLS, 'struct'):
                base['HasTlsCallbacks'] = 1.0 if getattr(pe.DIRECTORY_ENTRY_TLS.struct, 'AddressOfCallBacks', 0) != 0 else 0.0
            
            if hasattr(pe, 'VS_FIXEDFILEINFO') and len(pe.VS_FIXEDFILEINFO) > 0:
                flags = getattr(pe.VS_FIXEDFILEINFO[0], 'FileFlags', 0)
                base['IsDebug'] = 1.0 if flags & 0x1 else 0.0
                base['IsPreRelease'] = 1.0 if flags & 0x2 else 0.0
                base['IsPatched'] = 1.0 if flags & 0x4 else 0.0
                base['IsPrivateBuild'] = 1.0 if flags & 0x8 else 0.0
                base['IsSpecialBuild'] = 1.0 if flags & 0x20 else 0.0

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                base['ImportCount'] = len(pe.DIRECTORY_ENTRY_IMPORT)
                func_count = 0
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if getattr(entry, 'dll', None):
                        try: dlls.add(entry.dll.decode('ascii', 'ignore').lower())
                        except Exception: pass
                    for imp in getattr(entry, 'imports', []):
                        func_count += 1
                        if getattr(imp, 'name', None):
                            try: apis.add(imp.name.decode('ascii', 'ignore'))
                            except Exception: pass
                base['ImportFunctionCount'] = func_count

            base['ExportCount'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if (hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and hasattr(pe.DIRECTORY_ENTRY_EXPORT, 'symbols')) else 0.0

            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                icon_count = 0
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if getattr(entry, 'id', None) == 3 and hasattr(entry, 'directory'):
                        icon_count += len(getattr(entry.directory, 'entries', []))
                base['IconCount'] = icon_count
            else: 
                base['IconCount'] = 0.0

            base['DebugCount'] = len(pe.DIRECTORY_ENTRY_DEBUG) if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else 0.0

            base.update(cls._extract_overlay_features(pe, fsize))
            base.update(cls._extract_rich_header(pe))
            base.update(cls._extract_ep_anomalies(pe))
            base.update(cls._extract_advanced_resources(pe))
            base.update(cls._extract_load_config(pe))
            base.update(cls._extract_security_directory(pe, file_bytes, fsize))

            for k in base: base[k] = cls._safe_float(base[k])
            return {"Base": base, "DLLs": list(dlls), "APIs": list(apis)}

        except Exception: return None
        finally:
            if pe: pe.close()

####################################################################################################

def load_existing_hashes():
    hashes = set()
    if os.path.exists(JSONL_PATH):
        with open(JSONL_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    data = JSON_LOADS(line)
                    if 'FileHash' in data: hashes.add(data['FileHash'])
                except Exception: pass
    return hashes

####################################################################################################

GLOBAL_HASHES = set()

def worker_init(shared_hashes):
    global GLOBAL_HASHES
    GLOBAL_HASHES = shared_hashes

def _extract_worker_wrapper(args):
    return _extract_worker(*args)

def _extract_worker(file_path, label):
    try:
        fsize = os.path.getsize(file_path)
        if fsize == 0 or fsize > MAX_FILE_SIZE:
            return 'error', None

        with open(file_path, "rb") as f:
            file_bytes = f.read()

        sha256 = hashlib.sha256(file_bytes).hexdigest()
        
        if sha256 in GLOBAL_HASHES:
            return 'skipped', None

        res = FeatureExtractor.extract(file_bytes, file_path, fsize)
        if res:
            final_res = {"Label": label, "FileHash": sha256, **res}
            return 'success', (sha256, JSON_DUMPS(final_res) + "\n")
            
        return 'error', None
    except Exception:
        return 'error', None

####################################################################################################

def scan_and_save(path, label, existing_hashes):
    print(f"\n[*] Scanning path: {path} (Label={label})")
    files = [path] if os.path.isfile(path) else [os.path.join(r, f) for r, _, fs in os.walk(path) for f in fs]
    
    total = len(files)
    if total == 0:
        print("[-] No files found.")
        return

    print(f"[*] Found {total} files. Starting {MAX_WORKERS}-process extraction...\n")
    if HAS_ORJSON:
        print("[+] orjson acceleration enabled.")
    
    count, errors, skipped, processed_files = 0, 0, 0, 0
    start_time = time.time()
    batch_buffer = []
    
    pool = multiprocessing.Pool(processes=MAX_WORKERS, initializer=worker_init, initargs=(existing_hashes,))
    tasks = [(fpath, label) for fpath in files]
    
    try:
        for status, data in pool.imap_unordered(_extract_worker_wrapper, tasks):
            processed_files += 1
            
            if status == 'error':
                errors += 1
            elif status == 'skipped':
                skipped += 1
            elif status == 'success':
                sha256, json_str = data
                if sha256 not in existing_hashes:
                    existing_hashes.add(sha256)
                    batch_buffer.append(json_str)
                    count += 1
                else:
                    skipped += 1

            if len(batch_buffer) >= BATCH_SIZE:
                with open(JSONL_PATH, 'a', encoding='utf-8') as f_out:
                    f_out.writelines(batch_buffer)
                batch_buffer.clear()

            elapsed = time.time() - start_time
            rate = processed_files / elapsed if elapsed > 0 else 0
            sys.stdout.write(f"\r[{processed_files}/{total}] Added: {count} | Skipped: {skipped} | Errors: {errors} | Speed: {rate:.1f} files/s")
            sys.stdout.flush()

        pool.close()
        pool.join()

    except KeyboardInterrupt:
        print("\n\n[-] User aborted. Force terminating all child processes...")
        pool.terminate()
        pool.join()
    except Exception as e:
        print(f"\n[-] Critical error: {e}")
        pool.terminate()
        pool.join()
    finally:
        if batch_buffer:
            try:
                with open(JSONL_PATH, 'a', encoding='utf-8') as f_out:
                    f_out.writelines(batch_buffer)
            except Exception as save_err:
                print(f"\n[-] Failed to save remaining buffer: {save_err}")
        
        print(f"\n\n[+] Scan complete. Total added: {count}, Total skipped: {skipped}")

####################################################################################################

if __name__ == "__main__":
    multiprocessing.freeze_support() 
    
    print("\n---------------- PE Dataset Builder v4.0 ----------------\n")
    
    existing_hashes = load_existing_hashes()
    print(f"[+] Found {len(existing_hashes)} existing hashes.\n")

    try:
        while True:
            print("-" * 57)
            target_path = input("\n[*] Enter path (file or directory): ").strip().strip('"').strip("'")
            if target_path.lower() in ['exit', 'q']: break
            if not target_path or not os.path.exists(target_path):
                print("[-] Invalid path.")
                continue

            while True:
                label_input = input("[*] Enter label (0=Safe, 1=Malware): ").strip()
                if label_input.lower() in ['exit', 'q']: sys.exit()
                if label_input in ['0', '1']: break
                print("[-] Please enter 0 or 1.")

            scan_and_save(target_path, int(label_input), existing_hashes)
            
    except KeyboardInterrupt:
        print("\n\n[-] Aborted.")
