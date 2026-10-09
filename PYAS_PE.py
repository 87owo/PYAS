from PYAS_Diagnostics import log_exception
import os
import re
import json
import zlib
import numpy
from PYAS_Signature import SignatureScanner as sign_scanner
from PYAS_Features import PEFeatureMixin


class PEScanner(PEFeatureMixin):
    _STRING_PATTERN = re.compile(b"[\x20-\x7E]{5,}")

    _STRING_FAST_PATH_BYTES = 4194304

    _STRING_BATCH_BYTES = 4194304

    _HISTOGRAM_BATCH_WINDOWS = 1024

    _BYTE_HIST_KEYS = [f"ByteHist_{i:02X}" for i in range(256)]

    _BYTE_ENT_KEYS = [f"ByteEnt_{i:02X}" for i in range(256)]

    _STRING_KEYS = [f"StringHist_{i:02d}" for i in range(95)]

    _SECTION_HASH_KEYS = [f"SectionHash_{i:02d}" for i in range(50)]

    _CHAR_FLAGS = [
        0x00000020,
        0x00000040,
        0x00000080,
        0x02000000,
        0x20000000,
        0x40000000,
        0x80000000,
    ]

    _CHAR_COUNT_KEYS = {flag: f"Char_{flag:08X}_Count" for flag in _CHAR_FLAGS}

    _CHAR_ENT_KEYS = {flag: f"Char_{flag:08X}_MeanEntropy" for flag in _CHAR_FLAGS}

    _C_LOG_C_TABLE = numpy.zeros(2049, dtype=numpy.float64)

    _C_LOG_C_TABLE[1:] = numpy.arange(1, 2049) * numpy.log2(numpy.arange(1, 2049))

    _OPTIONAL_HEADER_FIELDS = [
        "Magic",
        "MajorLinkerVersion",
        "MinorLinkerVersion",
        "SizeOfCode",
        "SizeOfInitializedData",
        "SizeOfUninitializedData",
        "AddressOfEntryPoint",
        "BaseOfCode",
        "ImageBase",
        "SectionAlignment",
        "FileAlignment",
        "MajorOperatingSystemVersion",
        "MinorOperatingSystemVersion",
        "MajorImageVersion",
        "MinorImageVersion",
        "MajorSubsystemVersion",
        "MinorSubsystemVersion",
        "SizeOfImage",
        "SizeOfHeaders",
        "CheckSum",
        "Subsystem",
        "DllCharacteristics",
        "SizeOfStackReserve",
        "SizeOfStackCommit",
        "SizeOfHeapReserve",
        "SizeOfHeapCommit",
        "LoaderFlags",
        "NumberOfRvaAndSizes",
    ]

    _SECTION_DEFAULTS = {
        "SectionCount": 0.0,
        "SectionMaxEntropy": 0.0,
        "SectionMinEntropy": 0.0,
        "SectionMeanEntropy": 0.0,
        "SectionMaxRawSize": 0.0,
        "SectionMinRawSize": 0.0,
        "SectionMeanRawSize": 0.0,
        "SectionMaxVSize": 0.0,
        "SectionMinVSize": 0.0,
        "SectionMeanVSize": 0.0,
        "ExecutableSections": 0.0,
        "WritableSections": 0.0,
        "ReadableSections": 0.0,
        "SectionException": 0.0,
    }

    _CONDITIONAL_DEFAULTS = {
        "IsDriver": 0.0,
        "HasTlsCallbacks": 0.0,
        "IsDebug": 0.0,
        "IsPreRelease": 0.0,
        "IsPatched": 0.0,
        "IsPrivateBuild": 0.0,
        "IsSpecialBuild": 0.0,
        "ImportCount": 0.0,
        "ImportFunctionCount": 0.0,
        "ExportCount": 0.0,
        "IconCount": 0.0,
        "DebugCount": 0.0,
    }

    def __init__(self):
        self.model = None
        self.input_name = None
        self.feature_order = []
        self.feature_index = {}
        self.dll_hash_dim = 512
        self.api_hash_dim = 4096
        self.dll_hash_pad = 3
        self.api_hash_pad = 4
        self.signer = sign_scanner()
        self.signer.init_windll(["wintrust"])

    def load_path(self, path, callback=None):
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)

                if callback:
                    callback(full_path)

                if full_path.endswith(".onnx"):
                    self.load_model(full_path)

    def load_model(self, model_path):
        if not os.path.exists(model_path):
            return

        try:
            import onnxruntime

            model = onnxruntime.InferenceSession(model_path, providers=["CPUExecutionProvider"])
            input_name = model.get_inputs()[0].name
            feat_path = os.path.join(os.path.dirname(model_path), "features.json")
            feature_order = self.feature_order

            if os.path.exists(feat_path):
                with open(feat_path, "r", encoding="utf-8") as stream:
                    feature_order = json.load(stream)

            if not isinstance(feature_order, list) or any(
                not isinstance(feature, str) for feature in feature_order
            ):
                raise ValueError("Invalid model feature order")

            previous = (
                self.model,
                self.input_name,
                self.feature_order,
                self.feature_index,
                self.dll_hash_dim,
                self.api_hash_dim,
                self.dll_hash_pad,
                self.api_hash_pad,
            )

            try:
                self.feature_order = feature_order
                self._parse_hash_dims()
                self.input_name = input_name
                self.model = model
            except Exception:
                (
                    self.model,
                    self.input_name,
                    self.feature_order,
                    self.feature_index,
                    self.dll_hash_dim,
                    self.api_hash_dim,
                    self.dll_hash_pad,
                    self.api_hash_pad,
                ) = previous
                raise
        except Exception:
            log_exception("PEScanner.load_model")

    def _parse_hash_dims(self):
        self.feature_index = {feature: index for index, feature in enumerate(self.feature_order)}
        max_dll = -1
        max_api = -1

        for feat in self.feature_order:
            if feat.startswith("DllHash_"):
                try:
                    val_str = feat.split("_")[1]
                    max_dll = max(max_dll, int(val_str))
                    self.dll_hash_pad = len(val_str)
                except Exception:
                    log_exception("PYAS_PE.PEScanner._parse_hash_dims:127")
                    pass
            elif feat.startswith("ApiHash_"):
                try:
                    val_str = feat.split("_")[1]
                    max_api = max(max_api, int(val_str))
                    self.api_hash_pad = len(val_str)
                except Exception:
                    log_exception("PYAS_PE.PEScanner._parse_hash_dims:134")
                    pass

        if max_dll >= 0:
            self.dll_hash_dim = max_dll + 1

        if max_api >= 0:
            self.api_hash_dim = max_api + 1

    def pe_scan(self, file_path, enhanced_mode=False):
        if not self.model or not self.feature_order:
            return False, False

        try:
            raw_data = self.extract_features(file_path)

            if not raw_data:
                return False, False

            vec = numpy.zeros((1, len(self.feature_order)), dtype=numpy.float32)
            base = raw_data.get("Base", {})
            dlls = set(raw_data.get("DLLs", []))
            apis = set(raw_data.get("APIs", []))
            feat_map = self.feature_index

            for k, v in base.items():
                if k in feat_map:
                    vec[0, feat_map[k]] = v

            for d in dlls:
                old_fn = f"Dll_{d}"

                if old_fn in feat_map:
                    vec[0, feat_map[old_fn]] = 1.0

                h = zlib.crc32(d.encode("utf-8", "ignore")) % self.dll_hash_dim
                new_fn = f"DllHash_{h:0{self.dll_hash_pad}d}"

                if new_fn in feat_map:
                    vec[0, feat_map[new_fn]] += 1.0

            for a in apis:
                old_fn = f"Api_{a}"

                if old_fn in feat_map:
                    vec[0, feat_map[old_fn]] = 1.0

                h = zlib.crc32(a.encode("utf-8", "ignore")) % self.api_hash_dim
                new_fn = f"ApiHash_{h:0{self.api_hash_pad}d}"

                if new_fn in feat_map:
                    vec[0, feat_map[new_fn]] += 1.0

            outputs = self.model.run(None, {self.input_name: vec})

            del raw_data, vec
            result = outputs[1]
            prob = 0.0

            if isinstance(result, list) and len(result) > 0:
                prob_dict = result[0]

                if hasattr(prob_dict, "get"):
                    prob = float(prob_dict.get(1, prob_dict.get("1", 0.0)))

            elif isinstance(result, numpy.ndarray):
                if result.ndim == 2 and result.shape[1] > 1:
                    prob = float(result[0][1])

            score = int(prob * 100)

            if score >= 80:
                return f"Malware:WinPE/General.{score}!ml", score
            elif enhanced_mode and score >= 50:
                return f"Suspicious:WinPE/General.{score}!ml", score

            return False, False
        except Exception:
            log_exception("PYAS_PE.PEScanner.pe_scan:203")
            return False, False
