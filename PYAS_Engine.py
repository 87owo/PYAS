import os, io, sys, time, json, yara
import numpy, pefile, onnxruntime
from PIL import Image, ImageShow

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
        except:
            pass

    def yr_scan(self, file_path):
        try:
            if isinstance(file_path, str):
                with open(file_path, "rb") as f:
                    file_path = f.read()
            for name, rules in self.rules.items():
                matchs_rules = rules.match(data=file_path)
                if matchs_rules:
                    return "Virus/Rules", matchs_rules
            return False, False
        except:
            return False, False

class DLScan:
    def __init__(self):
        self.models = {}
        self.detect = []
        self.values = 0
        self.shells = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!o',
        'cry', 'test', 'ace', 'yg', 'obr', 'tvm', 'dec', 'enc', 'b1_', 'base',
        'bss', 'clr_uef', 'cursors', 'trs_age', 'engine', 'enigma', 'protect',
        'nep', 'no_bbt', 'wpp_sf', 'retpol', 'rt', 'rwexec', 'rygs', 'poolmi',
        's:@', 'pgae', 'proxy', 'wisevec', 'segm', 'transit', 'vmp', 'extjmp',
        'upx', 'tracesup', 'res', 'lzma', 'malloc_h', 'miniex', 'ndr64', 'be',
        'mssmixer', 'wow', 'press', 'fio', 'pad', 'hexpthk', 'h~;', 'icapsec',
        'sanontcp', 'secur', 'asmstub', 'nsys_wr', 'orpc', 'pack', 'wow64svc',
        'uedbg', 'viahw', 'data', 'zk', 'fothk', 'qihoo']

    def load_model(self, file_path):
        try:
            ftype = str(f".{file_path.split('.')[-1]}").lower()
            if ftype in [".json", ".txt"]:
                with open(file_path, 'r') as f:
                    self.class_names = json.load(f)
            elif ftype in [".onnx"]:
                self.models[file_path] = onnxruntime.InferenceSession(file_path)
            self.values = self.class_names['Values']
            self.detect = self.class_names['Detect']
        except:
            pass

    def dl_scan(self, file_data):
        try:
            target_size, sim = tuple(self.class_names['Pixels']), {}
            image = self.preprocess_image(file_data, target_size)
            image_array = numpy.array(image).astype('float32') / 255.0
            image_expand = numpy.expand_dims(image_array, axis=0)
            for model_name, model in self.models.items():
                input_name = model.get_inputs()[0].name
                pre_answer = model.run(None, {input_name: image_expand})[0][0]
                number = numpy.argmax(pre_answer)
                label = self.class_names['Labels'][number].replace("\n", "")
                sim[label] = sim.setdefault(label, 0) + pre_answer[number]
            for local_label, sim_sum in sim.items():
                if sim_sum > len(self.models) / 2:
                    local_level = sim_sum / len(self.models)
                    return local_label, local_level * 100
            return False, False
        except:
            return False, False

    def get_type(self, file_path):
        try:
            match_data = {}
            ftype = str(f".{file_path.split('.')[-1]}").lower()
            if ftype in [".exe", ".dll", ".sys", ".scr", ".com"]:
                with pefile.PE(file_path, fast_load=True) as pe:
                    for section in pe.sections:
                        section_name = section.Name.decode('latin1').strip('\x00')
                        if (section.Characteristics & 0x00000020 and not
                        any(shell in section_name.lower() for shell in self.shells)):
                            match_data[section_name] = section.get_data()
            elif ftype in [".bat", ".vbs", ".ps1", ".cmd", ".js"]:
                with open(file_path, 'rb') as file:
                    match_data[ftype] = file.read()
            return match_data
        except:
            return {}

    def preprocess_image(self, file_data, target_size):
        file_data = numpy.frombuffer(file_data, dtype=numpy.uint8)
        data_count = len(file_data)
        wah = int(numpy.ceil(numpy.sqrt((data_count + 2) // 3)))
        image_array = numpy.zeros((wah * wah * 3,), dtype=numpy.uint8)
        image_array[:data_count] = file_data
        image_array = image_array.reshape((wah, wah, 3))
        image = Image.fromarray(image_array)
        return image.resize(target_size, Image.Resampling.LANCZOS)
