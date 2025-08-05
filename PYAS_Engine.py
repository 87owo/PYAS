import os, yara, numpy, locale, pefile, onnxruntime
from PIL import Image

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
                with open(file, "r") as f:
                    self.network.extend(line.strip() for line in f if line.strip())
        except Exception as e:
            print(e)

    def yara_scan(self, file_path):
        try:
            data = open(file_path, "rb").read() if isinstance(file_path, str) else file_path
            for rules in self.rules.values():
                matches = rules.match(data=data)
                if matches:
                    rule_name = str(matches[0])
                    label = rule_name.split("_")[0]
                    level = rule_name.split("_")[-1]
                    return f"Rules/{label}", level
            return False, False
        except Exception:
            return False, False

class model_scanner:
    SHELLS = {
        "0","1","2","3","4","5","6","7","8","9","cry","tvm","dec","enc","vmp","upx","aes","lzma","press","pack",
        "enigma","protect","secur","asmstub","base","bss","clr_uef","cursors","transit","trs_age","engine","fio",
        "fothk","h~;","icapsec","malloc_h","miniex","mssmixer","ndr64","nsys_wr","obr","wow","wow64svc","wpp_sf",
        "pad","pgae","poolmi","proxy","qihoo","retpol","uedbg","tracesup","rwexec","rygs","s:@","sanontcp","segm",
        "test","res","wisevec","viahwaes","orpc","nep","ace","extjmp","no_bbt","data","page","hexpthk"}

    def __init__(self):
        self.models = {}
        self.suffix = {".com", ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".wsf"}
        self.labels = ["Pefile/White", "Script/White", "Pefile/General", "Script/General"]
        self.detect = {"Pefile/General", "Script/General"}
        self.resize = (224, 224)

    def load_path(self, path):
        for root, _, files in os.walk(path):
            for file in files:
                self.load_file(os.path.join(root, file))

    def load_file(self, file):
        if file.lower().endswith('.onnx'):
            try:
                self.models[file] = onnxruntime.InferenceSession(file)
            except Exception as e:
                print(e)

    def is_valid_suffix(self, file_path):
        return os.path.splitext(file_path)[-1].lower() in self.suffix

    def model_scan(self, file_path):
        try:
            if not self.models or not self.is_valid_suffix(file_path):
                return False, False

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
        if not self.is_valid_suffix(file_path):
            return match_data
        try:
            with pefile.PE(file_path, fast_load=True) as pe:
                sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
                if bool(sec.VirtualAddress and sec.Size):
                    return {}
                for section in pe.sections:
                    name = section.Name.rstrip(b'\x00').decode('latin1').lower()
                    if (section.Characteristics & 0x00000020) and name not in self.SHELLS:
                        match_data[name] = section.get_data()
        except pefile.PEFormatError:
            with open(file_path, 'rb') as f:
                file_content = f.read()
            if self.is_text_file(file_content):
                match_data[os.path.splitext(file_path)[-1].lower()] = file_content
        return match_data
