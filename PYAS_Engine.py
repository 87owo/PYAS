import os, re, yara, time, math, json, numpy, base64, datetime, requests
import ctypes, ctypes.wintypes, hashlib, pefile, threading, onnxruntime

####################################################################################################

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.wintypes.DWORD),
        ("Data2", ctypes.wintypes.WORD),
        ("Data3", ctypes.wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8)
    ]

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

####################################################################################################

class sign_scanner:
    def __init__(self):
        self.verify = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

    def init_windll(self, path):
        for name in path:
            try:
                setattr(self, name.lower(), ctypes.WinDLL(name, use_last_error=True))
            except Exception:
                pass
        try:
            self.WinVerifyTrust = self.wintrust.WinVerifyTrust
            self.WinVerifyTrust.restype = ctypes.wintypes.LONG
            self.WinVerifyTrust.argtypes = [ctypes.wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
        except Exception:
            pass

####################################################################################################

    def sign_verify(self, file_path):
        if os.name != 'nt':
            return False
        try:
            fi = WINTRUST_FILE_INFO()
            fi.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
            fi.pcwszFilePath = os.path.abspath(file_path)
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
            return self.WinVerifyTrust(None, ctypes.byref(self.verify), ctypes.byref(td)) == 0
        except Exception:
            return False

####################################################################################################

class rule_scanner:
    def __init__(self):
        self.rules = None
        self.network = []

    def load_path(self, path, callback=None):
        yara_files = {}
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                if callback:
                    callback(full_path)
                ext = os.path.splitext(file)[1].lower()
                if ext in ('.yara', '.yar'):
                    namespace = os.path.relpath(full_path, path).replace(os.sep, '_')
                    yara_files[namespace] = full_path
                elif ext in ('.yc', '.yrc'):
                    self.load_compiled_rule(full_path)
                elif ext in ('.ip', '.txt'):
                    self.load_network_list(full_path)

        if yara_files:
            self.compile_all_rules(yara_files)

####################################################################################################

    def load_compiled_rule(self, file):
        try:
            self.rules = yara.load(file)
        except Exception:
            pass

    def load_network_list(self, file):
        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                self.network.extend(line.strip() for line in f if line.strip())
        except Exception:
            pass

    def compile_all_rules(self, file_map):
        try:
            self.rules = yara.compile(filepaths=file_map)
        except Exception:
            pass

####################################################################################################

    def yara_scan(self, file_path):
        try:
            if not self.rules:
                return False, False

            matches = self.rules.match(filepath=file_path)
            if matches:
                rule_name = str(matches[0])
                label = rule_name.split("_")[0]
                level = rule_name.split("_")[-1]
                return f"{label}:WinPE/Unknown.A!rb", level
            return False, False
        except Exception:
            return False, False

####################################################################################################

class pe_scanner:
    def __init__(self):
        self.model = None
        self.input_name = None
        self.feature_order = []
        self.signer = sign_scanner()
        self.signer.init_windll(["wintrust"])

    def load_path(self, path, callback=None):
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                if callback:
                    callback(full_path)
                if full_path.endswith('.onnx'):
                    self.load_model(full_path)

    def load_model(self, model_path):
        if not os.path.exists(model_path):
            return
        try:
            self.model = onnxruntime.InferenceSession(model_path, providers=['CPUExecutionProvider'])
            self.input_name = self.model.get_inputs()[0].name
            feat_path = os.path.join(os.path.dirname(model_path), "features.json")
            if os.path.exists(feat_path):
                with open(feat_path, 'r', encoding='utf-8') as f:
                    self.feature_order = json.load(f)
        except Exception:
            pass

    def _safe_float(self, val):
        try:
            f = float(val)
            if math.isinf(f) or math.isnan(f): 
                return 0.0
            return f
        except Exception:
            return 0.0

    def _calc_entropy(self, data):
        if not data: 
            return 0.0
        arr = numpy.frombuffer(data, dtype=numpy.uint8)
        counts = numpy.bincount(arr, minlength=256)
        probs = counts[counts > 0] / len(arr)
        return float(-numpy.sum(probs * numpy.log2(probs)))

    def _extract_overlay_features(self, pe, fsize):
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
            "OverlayEntropy": self._calc_entropy(overlay_data)
        }

    def _extract_rich_header(self, pe):
        if not hasattr(pe, 'RICH_HEADER') or not pe.RICH_HEADER:
            return {"HasRichHeader": 0.0, "RichHeaderCount": 0.0}
        return {
            "HasRichHeader": 1.0,
            "RichHeaderCount": float(len(pe.RICH_HEADER.values) // 2) if hasattr(pe.RICH_HEADER, 'values') else 0.0
        }

    def _extract_ep_anomalies(self, pe):
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

    def _extract_advanced_resources(self, pe):
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
                            entropies.append(self._calc_entropy(data))
                        except Exception:
                            continue
                            
        res_data["ResourceLangCount"] = float(len(langs))
        res_data["ResourceRCDataCount"] = float(rcdata_count)
        
        if entropies:
            res_data["ResourceMaxEntropy"] = max(entropies)
            res_data["ResourceMinEntropy"] = min(entropies)
            res_data["ResourceMeanEntropy"] = sum(entropies) / len(entropies)
            
        return res_data

    def _extract_load_config(self, pe):
        cfg = {"HasLoadConfig": 0.0, "HasCFG": 0.0, "HasSEHTable": 0.0}
        if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
            cfg["HasLoadConfig"] = 1.0
            struct = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
            if getattr(struct, 'GuardCFFunctionTable', 0) != 0:
                cfg["HasCFG"] = 1.0
            if getattr(struct, 'SEHandlerTable', 0) != 0:
                cfg["HasSEHTable"] = 1.0
        return cfg

    def _extract_security_directory(self, pe, file_bytes, fsize):
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

    def extract_features(self, file_path):
        pe = None
        try:
            fsize = os.path.getsize(file_path)
            if fsize == 0 or fsize > 536870912:
                return None

            with open(file_path, "rb") as f:
                file_bytes = f.read()

            base = {}
            dlls = set()
            apis = set()
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
            
            base['TrustSigned'] = 1.0 if self.signer.sign_verify(file_path) else 0.0
            base['FileEntropy'] = self._calc_entropy(file_bytes)
            base['FileSize'] = float(fsize)
            
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
                fields = [
                    'Magic', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode',
                    'SizeOfInitializedData', 'SizeOfUninitializedData', 'AddressOfEntryPoint',
                    'BaseOfCode', 'ImageBase', 'SectionAlignment', 'FileAlignment',
                    'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion',
                    'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion',
                    'MinorSubsystemVersion', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum',
                    'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit',
                    'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes'
                ]
                for f_field in fields:
                    base[f_field] = getattr(op, f_field, 0)
                
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
                entropies = []
                raw_sizes = []
                v_sizes = []
                exec_sec = 0
                write_sec = 0
                read_sec = 0
                sec_exc = 0
                
                for section in pe.sections:
                    try:
                        s_data = section.get_data()
                        s_entropy = self._calc_entropy(s_data)
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
                base['ExecutableSections'] = float(exec_sec)
                base['WritableSections'] = float(write_sec)
                base['ReadableSections'] = float(read_sec)
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
                if getattr(pe.DIRECTORY_ENTRY_TLS.struct, 'AddressOfCallBacks', 0) != 0:
                    base['HasTlsCallbacks'] = 1.0
            
            if hasattr(pe, 'VS_FIXEDFILEINFO') and len(pe.VS_FIXEDFILEINFO) > 0:
                flags = getattr(pe.VS_FIXEDFILEINFO[0], 'FileFlags', 0)
                base['IsDebug'] = 1.0 if flags & 0x1 else 0.0
                base['IsPreRelease'] = 1.0 if flags & 0x2 else 0.0
                base['IsPatched'] = 1.0 if flags & 0x4 else 0.0
                base['IsPrivateBuild'] = 1.0 if flags & 0x8 else 0.0
                base['IsSpecialBuild'] = 1.0 if flags & 0x20 else 0.0

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                base['ImportCount'] = float(len(pe.DIRECTORY_ENTRY_IMPORT))
                func_count = 0
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if getattr(entry, 'dll', None):
                        try:
                            dlls.add(entry.dll.decode('ascii', 'ignore').lower())
                        except Exception:
                            pass
                    for imp in getattr(entry, 'imports', []):
                        func_count += 1
                        if getattr(imp, 'name', None):
                            try:
                                apis.add(imp.name.decode('ascii', 'ignore'))
                            except Exception:
                                pass
                base['ImportFunctionCount'] = float(func_count)
            else:
                base['ImportCount'] = 0.0
                base['ImportFunctionCount'] = 0.0

            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and hasattr(pe.DIRECTORY_ENTRY_EXPORT, 'symbols'):
                base['ExportCount'] = float(len(pe.DIRECTORY_ENTRY_EXPORT.symbols))
            else:
                base['ExportCount'] = 0.0

            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                icon_count = 0
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if getattr(entry, 'id', None) == 3 and hasattr(entry, 'directory'):
                        icon_count += len(getattr(entry.directory, 'entries', []))
                base['IconCount'] = float(icon_count)
            else:
                base['IconCount'] = 0.0

            if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                base['DebugCount'] = float(len(pe.DIRECTORY_ENTRY_DEBUG))
            else:
                base['DebugCount'] = 0.0

            base.update(self._extract_overlay_features(pe, fsize))
            base.update(self._extract_rich_header(pe))
            base.update(self._extract_ep_anomalies(pe))
            base.update(self._extract_advanced_resources(pe))
            base.update(self._extract_load_config(pe))
            base.update(self._extract_security_directory(pe, file_bytes, fsize))

            for k in base:
                base[k] = self._safe_float(base[k])

            return {"Base": base, "DLLs": list(dlls), "APIs": list(apis)}

        except Exception:
            return None
        finally:
            if pe:
                pe.close()

    def pe_scan(self, file_path, enhanced_mode=False):
        if not self.model or not self.feature_order:
            return False, False
        try:
            raw_data = self.extract_features(file_path)
            if not raw_data:
                return False, False

            vec = numpy.zeros((1, len(self.feature_order)), dtype=numpy.float32)
            base = raw_data.get('Base', {})
            dlls = set(raw_data.get('DLLs', []))
            apis = set(raw_data.get('APIs', []))

            for i, feat in enumerate(self.feature_order):
                if feat.startswith('Dll_'):
                    if feat[4:] in dlls:
                        vec[0, i] = 1.0
                elif feat.startswith('Api_'):
                    if feat[4:] in apis:
                        vec[0, i] = 1.0
                else:
                    vec[0, i] = base.get(feat, 0.0)

            outputs = self.model.run(None, {self.input_name: vec})
            result = outputs[1]
            prob = 0.0

            if isinstance(result, list) and len(result) > 0:
                prob_dict = result[0]
                if hasattr(prob_dict, 'get'):
                    prob = float(prob_dict.get(1, prob_dict.get('1', 0.0)))
            elif isinstance(result, numpy.ndarray):
                if result.ndim == 2 and result.shape[1] > 1:
                    prob = float(result[0][1])

            score = int(prob * 100)
            
            if score >= 80:
                return f"General:WinPE/Malware.{score}!ml", score
            elif enhanced_mode and score >= 50:
                return f"General:WinPE/Suspicious.{score}!ml", score

            return False, False
        except Exception:
            return False, False

####################################################################################################

class cloud_scanner:
    def __init__(self):
        self.session = None
        self.api_host = None
        self.api_key = None
        self.timeout = 30
        self.lock = threading.RLock()

    def _init_session(self, api_host, api_key):
        with self.lock:
            if self.session is None or self.api_host != api_host or self.api_key != api_key:
                self.api_host = api_host.rstrip('/')
                self.api_key = api_key
                self.session = requests.Session()
                self.session.headers.update({"X-API-Key": api_key, "User-Agent": "PYAS-Engine/1.1"})

    def _request(self, method, endpoint, **kwargs):
        with self.lock:
            current_session = self.session
            current_host = self.api_host
            
        if not current_session:
            return None
            
        try:
            r = current_session.request(method, f"{current_host}{endpoint}", timeout=self.timeout, **kwargs)
            if r.status_code == 200:
                return r
        except Exception:
            pass
        return None

    def calc_hash(self, file_path, block_size=65536):
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(block_size), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

####################################################################################################

    def rescan(self, sha256, api_host, api_key):
        self._init_session(api_host, api_key)
        r = self._request("POST", f"/api/rescan/{sha256}")
        return r is not None and r.json().get('status') == 'success'

    def upload_file(self, file_path, api_host, api_key, chunk_size=5242880, need_rescan=False):
        try:
            self._init_session(api_host, api_key)
            sha256 = self.calc_hash(file_path)
            if not sha256:
                return False, None

            status_req = self._request("GET", f"/api/processing_status/{sha256}")
            if status_req:
                status_data = status_req.json()
                current_status = status_data.get('status')
                
                if current_status == 'done':
                    if need_rescan:
                        self.rescan(sha256, api_host, api_key)
                    return True, sha256
                elif current_status in ('queued', 'processing'):
                    return True, sha256

            file_size = os.path.getsize(file_path)
            if file_size > 104857600:
                return False, sha256

            if file_size > chunk_size:
                total_chunks = (file_size + chunk_size - 1) // chunk_size
                upload_id = os.urandom(16).hex()
                with open(file_path, 'rb') as f:
                    for i in range(total_chunks):
                        chunk_data = f.read(chunk_size)
                        headers = {
                            "X-Chunk-Index": str(i),
                            "X-Total-Chunks": str(total_chunks),
                            "X-Upload-ID": upload_id
                        }
                        
                        chunk_success = False
                        for _ in range(3):
                            r = self._request("POST", "/api/upload", files={'file': (os.path.basename(file_path), chunk_data)}, headers=headers)
                            if r:
                                chunk_success = True
                                break
                            time.sleep(1)
                            
                        if not chunk_success:
                            return False, sha256
                return True, sha256

            with open(file_path, 'rb') as f:
                file_data = f.read()
                
            for _ in range(3):
                r = self._request("POST", "/api/upload", files={'file': (os.path.basename(file_path), file_data)})
                if r:
                    return True, sha256
                time.sleep(1)
                
            return False, sha256
        except Exception:
            return False, None

####################################################################################################

    def get_result(self, sha256, api_host, api_key, max_retries=6, interval=10):
        try:
            if not sha256:
                return False
            self._init_session(api_host, api_key)

            is_done = False
            for _ in range(max_retries):
                r = self._request("GET", f"/api/processing_status/{sha256}")
                if r:
                    st = r.json().get('status', 'error')
                    if st == 'done':
                        is_done = True
                        break
                    if st in ['error', 'failed']:
                        return False
                time.sleep(interval)

            if not is_done:
                return False

            r = self._request("GET", f"/api/report/{sha256}")
            if r:
                data = r.json().get('data', {})
                metadata = data.get('metadata', {})
                label = metadata.get('label', 'Unsupport')
                score = metadata.get('score', 0)
                sims = data.get('similar', [])

                is_malicious = 'General' in label
                sim_malicious_count = 0
                valid_sim_count = 0
                for s in sims:
                    if s.get('similarity', 0) > 80:
                        valid_sim_count += 1
                        if "General" in s.get('label', ''):
                            sim_malicious_count += 1

                if is_malicious and (valid_sim_count == 0 or sim_malicious_count == valid_sim_count):
                    return f"General:WinPE/Unknown.{score}!cl"
        except Exception:
            pass
        return False
