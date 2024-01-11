import json

class ListCompressor:
    def __init__(self):
        self.model = {'ones': [], 'zero': [], 'word': {}}

    def save_model(self, file_name):
        with open(file_name, 'w') as f:
            json.dump(self.model, f)
        print(f"\nModel Is Saved In {file_name}")

    def load_model(self, model_data):
        if isinstance(model_data, str):
            with open(model_data, 'r') as f:
                model_data = json.load(f)
        self.model = model_data

    def train_model(self, ones, zero, min_count=1, max_ratio=1.0):
        unique_words = set([item for sublist in ones + zero for item in sublist])
        self.model['word'] = {word: idx for idx, word in enumerate(unique_words)}
        ones = [[self.model['word'][item] for item in lst] for lst in ones if len(lst) >= min_count and len(lst) / len(unique_words) <= max_ratio]
        zero = [[self.model['word'][item] for item in lst] for lst in zero if len(lst) >= min_count and len(lst) / len(unique_words) <= max_ratio]
        self.model['ones'].extend(ones)
        self.model['zero'].extend(zero)

    def simplify_lists(self, lists):
        return [list(set(lst)) for lst in lists]

    def predict(self, new_list, similarity=0.5):
        new_list = [self.model['word'].get(item, -1) for item in new_list if item in self.model['word']]
        if len(new_list) < 1:
            return False
        max_vfl = [len(set(new_list) & set(ones)) / len(set(new_list) | set(ones)) for ones in self.model['ones']]
        max_sfl = [len(set(new_list) & set(zero)) / len(set(new_list) | set(zero)) for zero in self.model['zero']]
        return max(max_vfl) >= max(max_sfl) and max(max_vfl) >= similarity
