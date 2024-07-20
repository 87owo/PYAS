import time, json, hashlib, numpy

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

    def train_model(self, label, data, batch_size=10000):
        start = time.time()
        print(f"Convert {label}")
        if label not in self.model:
            self.model[label] = []
        for i, x in enumerate(data, 1):
            build_text = self.build_text(x, batch_size)
            self.model[label].append(build_text)
            used = "{0:.2f}".format(time.time()-start)
            prefix, suffix = f'{i}/{len(data)}:', f'{used}s'
            self.progress_bar(i, len(data), prefix, suffix)

    def build_text(self, content, batch_size):
        sums, batch, count = [], [], {}
        for index, char in enumerate(content):
            count[char] = count.setdefault(char, 0) + 1
            combined_input = f"{count[char]}_{char}"
            hashes = hashlib.sha256(combined_input.encode('utf-8'))
            batch.append(hashes.digest())
            if len(batch) >= batch_size:
                sums.append(self.sum_hashes(batch))
                batch = []
        if batch:
            sums.append(self.sum_hashes(batch))
        combined_sums = numpy.sum(sums, 0) > len(content) / 2
        v = numpy.packbits(combined_sums).tobytes()
        return int.from_bytes(v, 'big')

    def sum_hashes(self, digests):
        bitarray = numpy.unpackbits(numpy.frombuffer(b''.join(digests), dtype='>B'))
        return numpy.sum(numpy.reshape(bitarray, (-1, 256)), 0)

    def progress_bar(self, items, total, prefix='', suffix='', length=50, fill='█'):
        percent = min(100.0, max(0.0, 100 * (items / float(total))))
        end_char = '\n' if percent >= 100 else '\r'
        percent_string = "{0:.2f}".format(percent)
        filled_length = int(length * items // total)
        bar = fill * filled_length + ' ' * (length - filled_length)
        print(f'\r{prefix: <15} |{bar}| {percent_string}% {suffix}', end=end_char)

    def predict_all(self, query, batch_size=10000):
        label_similarities = {}
        query_hash = self.build_text(query, batch_size)
        for label in self.model:
            max_similarity = 0
            for data_point in self.model[label]:
                similarity = self.similar(data_point, query_hash)
                if similarity > max_similarity:
                    max_similarity = similarity
            label_similarities[label] = max_similarity
        return label_similarities

    def predict(self, query, batch_size=10000):
        max_similarity, max_label = 0, None
        query_hash = self.build_text(query, batch_size)
        for label in self.model:
            for data_point in self.model[label]:
                similarity = self.similar(data_point, query_hash)
                if similarity > max_similarity:
                    max_similarity, max_label = similarity, label
        return max_label, max_similarity

    def similar(self, x, y):
        hamming_distance = bin(x ^ y).count('1')
        return 1 - hamming_distance / 256
