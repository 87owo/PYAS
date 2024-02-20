from simhash import Simhash
import json

class ListSimHash:
    def __init__(self):
        self.model = {"ones": [], "zero": []}

    def save_model(self, file_name):
        with open(file_name, 'w') as f:
            json.dump(self.model, f)
        print(f"\nModel Is Saved In {file_name}")

    def load_model(self, model_data):
        if isinstance(model_data, str):
            with open(model_data, 'r') as f:
                model_data = json.load(f)
        self.model = model_data

    def train_model(self, ones, zero):
        self.model["ones"] = [Simhash(" ".join(x)).value for x in ones]
        self.model["zero"] = [Simhash(" ".join(y)).value for y in zero]

    def predict(self, query, length=64):
        query_hash = Simhash(" ".join(query)).value
        max_ones = max(self.similar(x, query_hash, length) for x in self.model["ones"])
        max_zero = max(self.similar(y, query_hash, length) for y in self.model["zero"])
        return max_ones, max_zero

    def similar(self, x, y, length):
        hamming_distance = bin(x ^ y).count('1')
        similarity = 1 - hamming_distance / length
        return similarity

############################################################

'''

ones = [['a', 'b', 'c'], ['d', 'e', 'f']]
zero = [['1', '2', '3'], ['4', '5', '6']]

simhash_obj = ListSimHash()
simhash_obj.train_model(ones, zero)
simhash_obj.save_model('Model.json')

news = ['a', 'b', 'c', 'd']

simhash_obj = ListSimHash()
simhash_obj.load_model('Model.json')
print(simhash_obj.predict(news))

'''

############################################################
