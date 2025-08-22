import os, yara, numpy, onnxruntime
import ctypes, ctypes.wintypes, pefile
from PIL import Image

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
        with pefile.PE(file, fast_load=True) as pe:
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
        self.models = {}
        self.suffix = {
            ".com", ".dll", ".drv", ".exe", ".ocx", ".scr", ".sys",
            ".bat", ".cmd", ".html", ".js", ".php", ".ps1", ".vbs", ".wsf", ".xml"}
        self.labels = [
            "Pefile/White", "Script/White", "Pefile/General", "Script/General"]
        self.detect = {
            "Pefile/General", "Script/General"}
        self.resize = (224, 224)

    def load_path(self, path):
        for root, _, files in os.walk(path):
            for file in files:
                self.load_file(os.path.join(root, file))

    def load_file(self, file):
        if file.lower().endswith('.onnx'):
            try:
                self.models[file] = onnxruntime.InferenceSession(file)
            except Exception:
                return False

    def model_scan(self, file_path):
        try:
            model = next(iter(self.models.values()))
            shape = model.get_inputs()[0].shape
            channels = shape[-1] if shape[-1] in (1, 3) else (shape[1] if shape[1] in (1, 3) else 1)

            file_sections = self.get_type(file_path)
            if not file_sections:
                return False, False

            batch_images = [self.preprocess_image(data, self.resize, channels) for data in file_sections.values()]
            arr = numpy.stack([numpy.asarray(img).astype('float32') / 255.0 for img in batch_images])
            if arr.ndim == 3:
                arr = arr[..., None]
            if shape[-1] in (1, 3):
                model_input = arr
            elif shape[1] in (1, 3):
                model_input = arr.transpose(0, 3, 1, 2)
            else:
                return False, False

            input_name = model.get_inputs()[0].name
            predictions = model.run(None, {input_name: model_input})[0]

            label_scores = {label: [] for label in self.labels}
            for pre_answers in predictions:
                for k, score in enumerate(pre_answers):
                    label_scores[self.labels[k]].append(score)
            label_percentage = {label: (sum(scores)/len(scores))*100 for label, scores in label_scores.items() if scores}
            if not label_percentage:
                return False, False
            best_label, best_conf = max(label_percentage.items(), key=lambda x: x[1])
            if best_label in self.detect:
                return best_label, int(best_conf)
            return False, False
        except Exception:
            return False, False

    def preprocess_image(self, file_data, size, channels=1):
        width, height = size
        wah = int(numpy.ceil(numpy.sqrt(len(file_data) / channels)))
        arr = numpy.frombuffer(file_data, dtype=numpy.uint8)
        img = numpy.zeros(wah*wah*channels, dtype=numpy.uint8)
        img[:len(file_data)] = arr

        if channels == 1:
            image = Image.fromarray(img.reshape((wah, wah)), 'L')
        else:
            image = Image.fromarray(img.reshape((wah, wah, channels)), 'RGB')
        return image.resize((width, height), Image.Resampling.NEAREST)

    def is_text_file(self, content, sample_size=1024):
        raw = content[:sample_size]
        if not raw:
            return False
        text_char = set(range(32, 127)) | {9, 10, 13}
        nontext = sum(b not in text_char for b in raw)
        return nontext / len(raw) < 0.15

    def get_type(self, file_path):
        match_data = {}
        if not os.path.splitext(file_path)[-1].lower() in self.suffix:
            return match_data
        try:
            with pefile.PE(file_path, fast_load=True) as pe:
                sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
                if bool(sec.VirtualAddress and sec.Size):
                    return {}
                for section in pe.sections:
                    name = section.Name.rstrip(b'\x00').decode('latin1').lower()
                    if section.Characteristics & 0x00000020:
                        match_data[name] = section.get_data()
        except pefile.PEFormatError:
            with open(file_path, 'rb') as f:
                file_content = f.read()
            if self.is_text_file(file_content):
                match_data[os.path.splitext(file_path)[-1].lower()] = file_content
        return match_data
