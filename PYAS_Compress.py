import json

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
        self.model['word'] = model_data['word']
        self.model.update(model_data)

    def train_model(self, label, data):
        if label not in self.model:
            self.model[label] = []
        unique_words = set([item for sublist in data for item in sublist])
        self.model['word'] = {word: idx for idx, word in enumerate(unique_words)}
        self.model[label].extend([[self.model['word'][item] for item in lst] for lst in data])

    def predict(self, new_list):
        new_list = [self.model['word'].get(item, 1) for item in new_list if item in self.model['word']]
        for label, items in self.model.items():
            if label != 'word' and new_list in items:
                return label
        return None
