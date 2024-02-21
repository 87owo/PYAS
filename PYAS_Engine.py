import json, re, hashlib, numpy, time
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

    def train_model(self, ones, zero, feature=128, batch_size=1000, progress=True):
        self.progress = progress
        self.model["feature"] = feature
        self.model["batch_size"] = batch_size
        self.model["version"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.model["ones"] = [self.build_text(" ".join(x)) for x in ones]
        self.model["zero"] = [self.build_text(" ".join(y)) for y in zero]

    def build_text(self, content, width=4):
        sums, batch, count = [], [], 0
        content = ''.join(re.findall(r'[\w\u4e00-\u9fcc]+', content.lower()))
        features = [content[i:i + width] for i in range(max(len(content) - width + 1, 1))]
        features = {k: sum(1 for _ in g) for k, g in groupby(sorted(features))}
        total = len(features)
        for i, (f, w) in enumerate(features.items(), 1):
            count += w
            h = hashlib.md5(f.encode('utf-8')).digest()
            batch.append(h * w)
            if len(batch) >= self.model["batch_size"] or i == total:
                sums.append(self.sum_hashes(batch))
                batch = []
                if self.progress:
                    self.progress_bar(i, total, prefix=f'Block {i}/{total}:')
        combined_sums = numpy.sum(sums, 0)
        v = numpy.packbits(combined_sums > count / 2).tobytes()
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
        print(f'\r{prefix: <20} |{bar}| {percent_string}% {suffix}', end=end_char)

    def predict(self, query, progress=False):
        self.progress = progress
        query_hash = self.build_text(" ".join(query))
        max_ones = max(self.similar(x, query_hash) for x in self.model["ones"])
        max_zero = max(self.similar(y, query_hash) for y in self.model["zero"])
        return max_ones, max_zero

    def similar(self, x, y):
        hamming_distance = bin(x ^ y).count('1')
        similarity = 1 - hamming_distance / self.model["feature"]
        return similarity
