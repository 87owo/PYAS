import os, io, sys, time, json, yara
import numpy, onnxruntime
from PIL import Image#, ImageShow

class YRScan:
    def __init__(self):
        self.rules = {}
        self.network = []

    def load_rules(self, file_path):
        ftype = str(f".{file_path.split('.')[-1]}").lower()
        if ftype in [".yara", ".yar"]:
            self.rules[file_path] = yara.compile(file_path)
        elif ftype in [".yc", ".yrc"]:
            self.rules[file_path] = yara.load(file_path)
        elif ftype in [".ip", ".ips"]:
            with open(file_path, "r") as f:
                self.network += [l.strip() for l in f.readlines()]

    def yr_scan(self, file_path):
        try:
            if isinstance(file_path, str):
                with open(file_path, "rb") as f:
                    file_path = f.read()
            for name, rules in self.rules.items():
                if rules.match(data=file_path):
                    return True
            return False
        except:
            return False

class DLScan:
    def __init__(self):
        self.models = {}
        self.detect = []
        self.values = 100

    def load_model(self, file_path):
        ftype = str(f".{file_path.split('.')[-1]}").lower()
        if ftype in [".json", ".txt"]:
            self.class_names = json.load(open(file_path, 'r'))
        self.values = self.class_names['Values']
        self.detect = self.class_names['Detect']
        available_providers = onnxruntime.get_available_providers()
        preferred_providers = [
            'CUDAExecutionProvider', 'ROCmExecutionProvider',
            'OpenVINOExecutionProvider', 'DirectMLExecutionProvider',
            'AzureExecutionProvider', 'CPUExecutionProvider']
        providers = [p for p in preferred_providers if p in available_providers]
        for model in self.class_names['Models']:
            try:
                model_path = os.path.join(os.path.dirname(file_path), model)
                try:
                    self.models[model] = onnxruntime.InferenceSession(model_path, providers=providers)
                except Exception as e:
                    providers = ['CPUExecutionProvider']
                    self.models[model] = onnxruntime.InferenceSession(model_path, providers=providers)
            except:
                pass

    def dl_scan(self, file_path):
        try:
            if isinstance(file_path, str):
                ftype = str(f".{file_path.split('.')[-1]}").lower()
                if ftype in self.class_names['Suffix']:
                    with open(file_path, 'rb') as f:
                        file_path = f.read()
                else:
                    return False, False
            target_size, sim = tuple(self.class_names['Pixels']), {}
            image = self.preprocess_image(file_path, target_size)
            image_array = numpy.array(image).astype('float32') / 255.0
            image_expand = numpy.expand_dims(image_array, axis=0)
            for model_name, model in self.models.items():
                input_name = model.get_inputs()[0].name
                pre_answer = model.run(None, {input_name: image_expand})[0][0]
                number = numpy.argmax(pre_answer)
                label = self.class_names['Labels'][number].replace("\n", "")
                sim[label] = sim.setdefault(label, 0) + pre_answer[number]
            for local_label, sim_sum in sim.items():
                if sim[local_label] > len(self.models) / 2:
                    local_level = sim_sum / len(self.models)
            if ftype in str(f".{local_label.split('/')[-1].split('-')[0]}").lower(): #
                return local_label, local_level * 100
            return False, False
        except Exception as e:
            print(f"Error during scan: {e}")
            return False, False

    def preprocess_image(self, file_data, target_size): # New
        file_data = numpy.frombuffer(file_data, dtype=numpy.uint8)
        data_count = len(file_data)
        wah = int(numpy.ceil(numpy.sqrt((data_count + 2) // 3)))
        image_array = numpy.zeros((wah * wah * 3,), dtype=numpy.uint8)
        image_array[:data_count] = file_data
        image_array = image_array.reshape((wah, wah, 3))
        image = Image.fromarray(image_array) #ImageShow.show(image)
        return image.resize(target_size, Image.Resampling.LANCZOS)
