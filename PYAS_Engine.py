import os, yara, numpy, base64, onnxruntime
import ctypes, ctypes.wintypes, pefile
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
            except Exception as e:
                self.send_message(e, "warn", False)

        self.WinVerifyTrust = self.wintrust.WinVerifyTrust
        self.WinVerifyTrust.restype = ctypes.wintypes.LONG
        self.WinVerifyTrust.argtypes = [ctypes.wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]

    def is_sign(self, file_path):
        with pefile.PE(file_path, fast_load=True) as pe:
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
            return sec_dir.VirtualAddress != 0 and sec_dir.Size > 0

    def sign_verify(self, file_path):
        fi = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), file_path, None, None)
        data = WINTRUST_DATA(ctypes.sizeof(WINTRUST_DATA), None, None, 2, 0, 1,
            ctypes.pointer(fi), 1, None, None, 0, 0, None)
        s = self.WinVerifyTrust(None, ctypes.byref(self.verify), ctypes.byref(data))
        data.dwStateAction = 2
        self.WinVerifyTrust(None, ctypes.byref(self.verify), ctypes.byref(data))
        return s == 0

####################################################################################################

class rule_scanner:
    def __init__(self):
        self.rules = {}
        self.network = []

    def load_path(self, path):
        for root, _, files in os.walk(path):
            for file in files:
                self.load_file(os.path.join(root, file))

    def load_file(self, file):
        ext = os.path.splitext(file)[1].lower()
        try:
            if ext in ('.yara', '.yar'):
                self.rules[file] = yara.compile(file)
            elif ext in ('.yc', '.yrc'):
                self.rules[file] = yara.load(file)
            elif ext in ('.ip', '.txt'):
                with open(file, "r", encoding="utf-8", errors="ignore") as f:
                    self.network.extend(line.strip() for line in f if line.strip())
        except Exception:
            return False

    def yara_scan(self, file_path):
        try:
            for rules in self.rules.values():
                matches = rules.match(filepath=file_path)
                if matches:
                    rule_name = str(matches[0])
                    label = rule_name.split("_")[0]
                    level = rule_name.split("_")[-1]
                    return f"Rules/{label}", level
            return False, False
        except Exception:
            return False, False

####################################################################################################

class model_scanner:
    def __init__(self):
        self.model = None
        self.suffix = {".com", ".dll", ".drv", ".exe", ".ocx", ".scr", ".sys"}
        self.labels = ["Pefile/White", "Pefile/General"]
        self.detect_set = {"Pefile/General"}
        self.resize = (224, 224)

    def load_path(self, path):
        for root, _, files in os.walk(path):
            for file in files:
                self.load_file(os.path.join(root, file))

    def load_file(self, file):
        if file.lower().endswith('.onnx'):
            try:
                self.model = onnxruntime.InferenceSession(file)
            except Exception:
                return False

    def model_scan(self, file_path, full_output=False):
        if not self.model:
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

        input_meta = self.model.get_inputs()[0]
        input_name = input_meta.name
        input_shape = input_meta.shape

        if len(input_shape) == 4:
            if input_shape[1] in (1, 3) and input_shape[3] not in (1, 3):
                arr = arr.transpose(0, 3, 1, 2)
        try:
            probs = self.model.run(None, {input_name: arr})[0]
        except Exception:
            return (False, False) if not full_output else ([], str(file_path), None)

        results = []
        best_malicious = None

        for name, pred, img in zip(sections.keys(), probs, images):
            idx = int(numpy.argmax(pred))
            label = self.labels[idx] if idx < len(self.labels) else f"Class_{idx}"
            conf = round(float(pred[idx]) * 100, 2)
            print(f"Section: {name} | Label: {label} | Confidence: {conf}%")

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
                    for section in pe.sections:
                        name = section.Name.rstrip(b'\x00').decode('latin1', errors='ignore').lower()
                        data = section.get_data()
                        if data:
                            match_data[name] = data
            except Exception:
                pass
        return match_data
