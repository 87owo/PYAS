import os, yara, time, numpy, base64, requests
import ctypes, ctypes.wintypes, pefile, hashlib, onnxruntime

from PIL import Image
from io import BytesIO

####################################################################################################

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.wintypes.DWORD),
        ("Data2", ctypes.wintypes.WORD),
        ("Data3", ctypes.wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8)]

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pcwszFilePath", ctypes.wintypes.LPCWSTR),
        ("hFile", ctypes.wintypes.HANDLE),
        ("pgKnownSubject", ctypes.wintypes.LPVOID)]

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
        ("pSignatureSettings", ctypes.wintypes.LPVOID)]

####################################################################################################

class sign_scanner:
    def __init__(self):
        self.verify = GUID(0x00AAC56B, 0xCD44, 0x11D0, (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

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

    def is_sign(self, file_path):
        try:
            with pefile.PE(file_path, fast_load=True) as pe:
                sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
                return sec_dir.VirtualAddress != 0 and sec_dir.Size > 0
        except Exception:
            return False

    def sign_verify(self, file_path):
        try:
            fi = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), file_path, None, None)
            data = WINTRUST_DATA(ctypes.sizeof(WINTRUST_DATA), None, None, 2, 0, 1,
                ctypes.pointer(fi), 1, None, None, 0, 0, None)
            s = self.WinVerifyTrust(None, ctypes.byref(self.verify), ctypes.byref(data))
            data.dwStateAction = 2
            self.WinVerifyTrust(None, ctypes.byref(self.verify), ctypes.byref(data))
            return s == 0
        except Exception:
            return False

####################################################################################################

class rule_scanner:
    def __init__(self):
        self.suffix = {".com", ".dll", ".drv", ".exe", ".ocx", ".scr", ".sys", ".mui"}
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

    def yara_scan(self, file_path):
        try:
            if not self.rules:
                return False, False

            fpath_str = str(file_path)
            ext = os.path.splitext(fpath_str)[-1].lower()
            if ext not in self.suffix:
                return False, False

            matches = self.rules.match(filepath=file_path)
            if matches:
                rule_name = str(matches[0])
                types = rule_name.split("_")[0]
                label = rule_name.split("_")[1]
                level = rule_name.split("_")[2]
                return f"{types}/{label}", level
            return False, False
        except Exception:
            return False, False

####################################################################################################

class model_scanner:
    def __init__(self):
        self.models = []
        self.suffix = {".com", ".dll", ".drv", ".exe", ".ocx", ".scr", ".sys", ".mui"}
        self.labels = ["Pefile/White", "Pefile/General"]
        self.detect_set = {"Pefile/General"}
        self.resize = (224, 224)

    def load_path(self, path, callback=None):
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                if callback:
                    callback(full_path)
                self.load_file(full_path)

    def load_file(self, file):
        if file.lower().endswith('.onnx'):
            try:
                session = onnxruntime.InferenceSession(file)
                self.models.append(session)
            except Exception:
                return False

    def model_scan(self, file_path, full_output=False):
        if not self.models:
            return (False, False) if not full_output else ([], str(file_path), None)

        sections = self.extract_sections(file_path)
        if not sections:
            return (False, False) if not full_output else ([], str(file_path), None)
            
        images = [self.preprocess_image(data, self.resize) for data in sections.values()]
        if not images:
            return (False, False) if not full_output else ([], str(file_path), None)

        arr = numpy.stack([numpy.asarray(img).astype('float32') / 255.0 for img in images])
        if arr.ndim == 3:
            arr = numpy.expand_dims(arr, axis=-1)

        results = []
        best_malicious = None

        for model in self.models:
            input_meta = model.get_inputs()[0]
            input_name = input_meta.name
            input_shape = input_meta.shape
            
            curr_arr = arr.copy()
            if len(input_shape) == 4:
                if input_shape[1] in (1, 3) and input_shape[3] not in (1, 3):
                    curr_arr = curr_arr.transpose(0, 3, 1, 2)
            
            try:
                probs = model.run(None, {input_name: curr_arr})[0]
            except Exception:
                continue

            for name, pred, img in zip(sections.keys(), probs, images):
                idx = int(numpy.argmax(pred))
                label = self.labels[idx] if idx < len(self.labels) else f"Class_{idx}"
                conf = round(float(pred[idx]) * 100, 2)

                if full_output:
                    results.append((name, label, conf, self.pil_to_base64(img)))
                
                if label in self.detect_set:
                    if best_malicious is None or conf > best_malicious[1]:
                        best_malicious = (label, int(conf))

        if full_output:
            results.sort(key=lambda x: (x[1] not in self.detect_set, -x[2]))
            malicious_count = sum(1 for _, lbl, _, _ in results if lbl in self.detect_set)
            total = len(results)
            return results, str(file_path), f"{malicious_count}/{total}"

        return best_malicious if best_malicious else (False, False)

    def pil_to_base64(self, img):
        buf = BytesIO()
        img.save(buf, format='PNG')
        return base64.b64encode(buf.getvalue()).decode()

    def preprocess_image(self, data, size, channels=1):
        width, height = size
        wah = int(numpy.ceil(numpy.sqrt(len(data) / channels)))
        arr = numpy.frombuffer(data, dtype=numpy.uint8)
        imgbuf = numpy.zeros(wah * wah * channels, dtype=numpy.uint8)
        imgbuf[:len(arr)] = arr
        image = Image.fromarray(imgbuf.reshape((wah, wah)), 'L')
        return image.resize((width, height), Image.Resampling.NEAREST)

    def extract_sections(self, file_path):
        match_data = {}
        fpath_str = str(file_path)
        ext = os.path.splitext(fpath_str)[-1].lower()
        if ext in self.suffix:
            try:
                with pefile.PE(fpath_str, fast_load=True) as pe:
                    for i, section in enumerate(pe.sections):
                        try:
                            name = section.Name.rstrip(b'\x00').decode('latin1', errors='ignore').lower()
                        except:
                            name = f"section_{i}"
                        data = section.get_data()
                        if data:
                            match_data[f"{name}_{i}"] = data
            except Exception:
                pass
        return match_data

####################################################################################################

class cloud_scanner:
    def __init__(self):
        pass

    def calc_hash(self, file_path, block_size=65536):
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(block_size), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def upload_file(self, file_path, api_host, api_key):
        try:
            sha256 = self.calc_hash(file_path)
            if not sha256:
                return False, None

            base = api_host.rstrip('/')
            base_headers = {"X-API-Key": api_key, "User-Agent": "PYAS-Client/1.0"}

            def _req(m, ep, files=None, **k):
                try:
                    return requests.request(m, f"{base}{ep}", headers=base_headers, files=files, timeout=120, **k)
                except:
                    return None

            r = _req("GET", f"/api/processing_status/{sha256}")
            status = r.json().get('status') if r and r.status_code == 200 else 'missing'
            if status in ['failed', 'error']:
                status = 'missing'

            if status == 'missing':
                with open(file_path, 'rb') as f:
                    r = _req("POST", "/api/upload", files={'file': f})
                    if not r or r.status_code != 200:
                        return False, sha256

            return True, sha256
        except Exception:
            return False, None

    def get_result(self, sha256, api_host, api_key):
        try:
            if not sha256:
                return False

            base = api_host.rstrip('/')
            headers = {"X-API-Key": api_key, "User-Agent": "PYAS-Client/1.0"}

            def _req(m, ep, **k):
                try:
                    return requests.request(m, f"{base}{ep}", headers=headers, timeout=10, **k)
                except:
                    return None

            for _ in range(30):
                r = _req("GET", f"/api/processing_status/{sha256}")
                st = r.json().get('status') if r else 'error'
                if st == 'done':
                    break
                if st in ['error', 'failed']:
                    return False
                time.sleep(1)

            r = _req("GET", f"/api/report/{sha256}")
            if r and r.status_code == 200:
                data = r.json().get('data', {})
                res = data.get('detection', {}).get('results', {}).get('PYAS', {})
                label = res.get('label', 'Unsupport')
                sims = data.get('similar', [])

                is_malicious = 'General' in label
                sim_malicious_count = 0
                valid_sim_count = 0
                for s in sims:
                    if s.get('similarity', 0) > 80:
                        valid_sim_count += 1
                        if "General" in s.get('label'):
                            sim_malicious_count += 1

                if is_malicious and (valid_sim_count == 0 or sim_malicious_count == valid_sim_count):
                    return True
        except Exception:
            pass
        return False
