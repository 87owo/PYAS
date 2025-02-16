import os, sys, time, json, yara, numpy
import chardet, pefile, onnxruntime
from PIL import Image

class YRScan:
    def __init__(self):
        self.rules = {}
        self.network = []

    def load_rules(self, file_path):
        try:
            ftype = os.path.splitext(file_path)[-1].lower()
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
        self.valid_interpolations = {
        "box": Image.Resampling.BOX,
        "none": Image.Resampling.NEAREST,
        "bilinear": Image.Resampling.BILINEAR,
        "hamming": Image.Resampling.HAMMING,
        "bicubic": Image.Resampling.BICUBIC,
        "lanczos": Image.Resampling.LANCZOS,
        "nearest": Image.Resampling.NEAREST}

        shell_section = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", 
        "cry", "tvm", "dec", "enc", "vmp", "upx", "aes", "lzma", "press", 
        "pack", "enigma", "protect", "secur"]
        unknown_section = ["asmstub", "base", "bss", "clr_uef", "cursors", 
        "engine", "fio", "fothk", "h~;", "icapsec", "malloc_h", "miniex", 
        "mssmixer", "ndr64", "nsys_wr", "obr", "wow", "wow64svc", "wpp_sf",
        "pad", "pgae", "poolmi", "proxy", "qihoo", "res", "retpol", "uedbg",
        "rwexec", "rygs", "s:@", "sanontcp", "segm", "test", "tracesup",
        "transit", "trs_age", "wisevec"]
        unimportant_section = ["viahwaes", "orpc", "nep", "ace", "extjmp", 
        "no_bbt", "data", "page", "hexpthk"]
        self.shells = shell_section + unimportant_section + unknown_section

    def load_model(self, file_path):
        try:
            ftype = os.path.splitext(file_path)[-1].lower()
            if ftype in [".json", ".txt"]:
                with open(file_path, 'r') as f:
                    self.class_names = json.load(f)
            elif ftype in [".onnx"]:
                self.models[file_path] = onnxruntime.InferenceSession(file_path)
            self.labels = self.class_names['Labels']
            self.detect = self.class_names['Detect']
            self.values = self.class_names['Values']
            self.resize = self.class_names['Resize']
            self.suffix = self.class_names['Suffix']
        except Exception as e:
            pass

    def dl_scan(self, file_path):
        try:
            batch_images = []
            for section, file_data in self.get_type(file_path).items():
                image_data = self.preprocess_image(file_data, tuple(self.resize))
                image_array = numpy.asarray(image_data).astype('float32') / 255.0
                if len(image_array.shape) == 2:
                    image_array = numpy.expand_dims(image_array, axis=-1)
                batch_images.append(image_array)
            batch_results = [{label: [] for label in self.labels} for _ in range(len(batch_images))]
            batch_images = numpy.stack(batch_images, axis=0)
            for model_name, model in self.models.items():
                input_name = model.get_inputs()[0].name
                predictions = model.run(None, {input_name: batch_images})[0]
                for i, pre_answers in enumerate(predictions):
                    for k, score in enumerate(pre_answers):
                        batch_results[i][self.labels[k].strip()].append(score)
            final_results = []
            for result in batch_results:
                label_percentage = {label: (sum(scores) / len(scores)) * 100
                for label, scores in result.items()}
                best_label, best_confidence = max(label_percentage.items(), key=lambda x: x[1])
                final_results.append((best_label, int(best_confidence)))
                if best_label in self.detect:
                    return best_label, int(best_confidence)
            return False, False
        except Exception as e:
            return False, False

    def preprocess_image(self, file_data, target_size):
        width, height, channels, interpolation = target_size
        wah = int(numpy.ceil(numpy.sqrt(len(file_data) / channels)))
        array_data = numpy.frombuffer(file_data, dtype=numpy.uint8)
        expected_size = wah * wah * channels
        image_array = numpy.zeros((expected_size,), dtype=numpy.uint8)
        image_array[:len(file_data)] = array_data
        if channels == 1:
            reshape = image_array.reshape((wah, wah))
            image = Image.fromarray(reshape, 'L')
        elif channels == 3:
            reshape = image_array.reshape((wah, wah, 3))
            image = Image.fromarray(reshape, 'RGB')
        if width == 0 and height == 0:
            return image
        i = self.valid_interpolations.get(interpolation.lower(), Image.BILINEAR)
        return image.resize((width, height), i)

    def is_text_file(self, content, sample_size):
        try:
            raw_data = content[:sample_size]
            encoding = chardet.detect(raw_data)["encoding"]
            if encoding in ["ascii", "utf-8", "utf-8-sig"]:
                if raw_data.decode(encoding):
                    return True
            return False
        except:
            return False

    def get_type(self, file_path):
        match_data = {}
        ftype = os.path.splitext(file_path)[-1].lower()
        if ftype in self.suffix:
            try:
                with pefile.PE(file_path, fast_load=True) as pe:
                    for section in pe.sections:
                        name = section.Name.rstrip(b'\x00').decode('latin1')
                        if (section.Characteristics & 0x00000020 and not
                        any(s in name.lower() for s in self.shells)):
                            print(name)
                            match_data[name] = section.get_data()
            except:
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                if self.is_text_file(file_content, 1024):
                    match_data[ftype] = file_content
        return match_data
