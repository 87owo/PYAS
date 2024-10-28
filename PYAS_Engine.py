import os, sys, time, json, yara
import numpy, pefile, onnxruntime
from PIL import Image

class YRScan:
    def __init__(self):
        self.rules = {}
        self.network = []

    def load_rules(self, file_path):
        try:
            ftype = str(f".{file_path.split('.')[-1]}").lower()
            if ftype in [".yara", ".yar"]:
                self.rules[file_path] = yara.compile(file_path)
            elif ftype in [".yc", ".yrc"]:
                self.rules[file_path] = yara.load(file_path)
            elif ftype in [".ip", ".ips"]:
                with open(file_path, "r") as f:
                    self.network += [l.strip() for l in f.readlines()]
        except Exception as e:
            print(e)

    def yr_scan(self, file_path):
        try:
            if isinstance(file_path, str):
                with open(file_path, "rb") as f:
                    file_path = f.read()
            for name, rules in self.rules.items():
                matchs_rules = rules.match(data=file_path)
                if matchs_rules:
                    label = str(matchs_rules[0]).split("_")[0]
                    level = str(matchs_rules[0]).split("_")[-1]
                    return f"Rules/{label}", level
            return False, False
        except Exception as e:
            return False, False

class DLScan:
    def __init__(self):
        self.models = {}
        self.shells = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!o',
        'cry', 'test', 'ace', 'yg', 'obr', 'tvm', 'dec', 'enc', 'b1_', 'base',
        'bss', 'clr_uef', 'cursors', 'trs_age', 'engine', 'enigma', 'protect',
        'nep', 'no_bbt', 'wpp_sf', 'retpol', 'rt', 'rwexec', 'rygs', 'poolmi',
        's:@', 'pgae', 'proxy', 'wisevec', 'segm', 'transit', 'vmp', 'extjmp',
        'upx', 'tracesup', 'res', 'lzma', 'malloc_h', 'miniex', 'ndr64', 'be',
        'mssmixer', 'wow', 'press', 'fio', 'pad', 'hexpthk', 'h~;', 'icapsec',
        'sanontcp', 'secur', 'asmstub', 'nsys_wr', 'orpc', 'pack', 'wow64svc',
        'uedbg', 'viahw', 'data', 'zk', 'fothk', 'qihoo']#"""

    def load_model(self, file_path):
        try:
            ftype = str(f".{file_path.split('.')[-1]}").lower()
            if ftype in [".json", ".txt"]:
                with open(file_path, 'r') as f:
                    self.class_names = json.load(f)
            elif ftype in [".onnx"]:
                self.models[file_path] = onnxruntime.InferenceSession(file_path)
            self.labels = self.class_names['Labels']
            self.detect = self.class_names['Detect']
            self.pixels = self.class_names['Pixels']
            self.values = self.class_names['Values']
            self.suffix = self.class_names['Suffix']
        except Exception as e:
            pass

    def dl_scan(self, file_data):
        try:
            label_similarities = {label: [] for label in self.labels}
            image_data = self.preprocess_image(file_data, tuple(self.pixels))
            image_array = numpy.asarray(image_data).astype('float32') / 255.0
            image_expand = numpy.expand_dims(image_array, axis=(0, -1))
            for model_name, model in self.models.items():
                input_name = model.get_inputs()[0].name
                pre_answers = model.run(None, {input_name: image_expand})[0][0]
                for k, score in enumerate(pre_answers):
                    label_similarities[self.labels[k].strip()].append(score)
            label_percentage = {label: (sum(similarities) / len(image_expand)) * 100
            for label, similarities in label_similarities.items()}
            label, level = max(label_percentage.items(), key=lambda x: x[1])
            return label, int(level)
        except Exception as e:
            return False, False

    def preprocess_image(self, file_data, target_size):
        wah = int(numpy.ceil(numpy.sqrt(len(file_data))))
        file_data = numpy.frombuffer(file_data, dtype=numpy.uint8)
        image_array = numpy.zeros((wah * wah,), dtype=numpy.uint8)
        image_array[:len(file_data)] = file_data
        image = Image.fromarray(image_array.reshape((wah, wah)), 'L')
        return image.resize(target_size, Image.Resampling.NEAREST)

    def get_type(self, file_path):
        match_data = {}
        ftype = str(f".{file_path.split('.')[-1]}").lower()
        if ftype in self.suffix:
            try:
                with pefile.PE(file_path, fast_load=True) as pe:
                    for section in pe.sections:
                        section_name = section.Name.rstrip(b'\x00').decode('latin1')
                        if (section.Characteristics & 0x00000020 and not
                        any(shell in section_name.lower() for shell in self.shells)):
                            match_data[section_name] = section.get_data()
            except:
                if ftype in [".bat", ".cmd", ".ps1", ".vbs", ".wsf", ".html", ".js", 
                    ".txt", ".htm", ".hta", ".php", ".css", ".xml", ".json", ".wasm"]:
                    with open(file_path, 'rb') as file:
                        match_data[ftype] = file.read()
        return match_data
