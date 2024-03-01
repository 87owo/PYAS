import time, json, hashlib, numpy
from itertools import groupby

class ListSimHash:
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

    def get_model(self, label):
        return self.model[label]

    def train_model(self, ones, zero, feature=128, batch=1000):
        self.model["feature"] = feature
        self.model["batch"] = batch
        self.model["ones"] = []
        self.model["zero"] = []
        start = time.time()
        print("Convert ones")
        for i, x in enumerate(ones, 1):
            self.model["ones"].append(self.build_text(x))
            used = "{0:.2f}".format(time.time()-start)
            self.progress_bar(i, len(ones), prefix=f'{i}/{len(ones)}:', suffix=f'{used}s')
        start = time.time()
        print("Convert zero")
        for i, y in enumerate(zero, 1):
            self.model["zero"].append(self.build_text(y))
            used = "{0:.2f}".format(time.time()-start)
            self.progress_bar(i, len(zero), prefix=f'{i}/{len(zero)}:', suffix=f'{used}s')

    def build_text(self, content):
        sums, batch, count = [], [], 0
        features = {k: sum(1 for _ in g) for k, g in groupby(sorted(content))}
        for f, w in features.items():
            count += w
            h = hashlib.md5(f.encode('utf-8')).digest()
            batch.append(h * w)
            if len(batch) >= self.model["batch"]:
                sums.append(self.sum_hashes(batch))
                batch = []
        if batch:
            sums.append(self.sum_hashes(batch))
        v = numpy.packbits(numpy.sum(sums, 0) > count / 2).tobytes()
        return int.from_bytes(v, 'big')

    def sum_hashes(self, digests):
        bitarray = numpy.unpackbits(numpy.frombuffer(b''.join(digests), dtype='>B'))
        return numpy.sum(numpy.reshape(bitarray, (-1, self.model["feature"])), 0)

    def progress_bar(self, iteration, total, prefix='', suffix='', length=50, fill='█'):
        percent = min(100.0, max(0.0, 100 * (iteration / float(total))))
        end_char = '\n' if percent >= 100 else '\r'
        percent_string = "{0:.2f}".format(percent)
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + ' ' * (length - filled_length)
        print(f'\r    {prefix: <10} |{bar}| {percent_string}% {suffix}', end=end_char)

    def predict(self, query):
        query_hash = self.build_text(query)
        max_ones = max(self.similar(x, query_hash) for x in self.model["ones"])
        max_zero = max(self.similar(y, query_hash) for y in self.model["zero"])
        return max_ones, max_zero

    def similar(self, x, y):
        hamming_distance = bin(x ^ y).count('1')
        similarity = 1 - hamming_distance / self.model["feature"]
        return similarity
