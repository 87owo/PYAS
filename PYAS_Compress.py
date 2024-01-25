import json, hashlib

class ListCompressor:
    def __init__(self):
        self.model = {}

    def save_model(self, file_name):
        with open(file_name, 'w') as f:
            json.dump(self.model, f)
        print(f"\nModel Is Saved In {file_name}")

    def load_model(self, model_data):
        if isinstance(model_data, str):
            with open(model_data, 'r') as f:
                model_data = json.load(f)
        self.model = model_data

    def train_model(self, label, data):
        if label not in self.model:
            self.model[label] = []
        for lst in data:
            self.model[label].append(hashlib.md5(''.join(map(str, lst)).encode()).hexdigest()[:8])

    def predict(self, new_list):
        for label, items in self.model.items():
            if label != 'word' and hashlib.md5(''.join(map(str, new_list)).encode()).hexdigest()[:8] in items:
                return True
        return False

    def get_label(self):
        return list(self.model.keys())[0]
