from collections import defaultdict
import math, json, time, types, random

class ListClassifier:
    def __init__(self):
        self.word_weights = defaultdict(lambda: {'ones': 0, 'zero': 0})
        self.total_counts = {'ones': 0, 'zero': 0}
        self.prior_probs = {'ones': 0, 'zero': 0}
        self.class_weights = {'ones': 1, 'zero': 1}
        self.min_quantity = 0
        self.max_quantity = 1.0
        self.learning_rate = 0.1
        self.max_sequence = 100
        self.test_data = []
        self.train_data = []

    def load_model(self, model_data):
        if isinstance(model_data, str):
            with open(model_data, 'r') as f:
                model_data = json.load(f)
        self.word_weights = defaultdict(lambda: {'ones': 0, 'zero': 0})
        self.word_weights.update(model_data['word_weights'])
        self.total_counts = model_data['total_counts']
        self.prior_probs = model_data['prior_probs']
        self.max_sequence = model_data.get('max_sequence')

    def save_model(self, filename):
        model_data = {
            'word_weights': dict(self.word_weights),
            'total_counts': self.total_counts,
            'prior_probs': self.prior_probs,
            'max_sequence': self.max_sequence}
        with open(filename, 'w') as f:
            json.dump(model_data, f)
        print(f"\nModel Is Safe In {filename}")

    def train_model(self, ones_data, zero_data, epochs=1, batch_size=32, min_quantity=0, max_quantity=1.0, max_sequence=10, test_size=0.2, learning_rate=None, random_seed=None, class_weights=None):
        self.min_quantity = min_quantity
        self.max_quantity = max_quantity
        self.max_sequence = max_sequence
        self.learning_rate = learning_rate if learning_rate is not None else self.learning_rate
        self.class_weights = class_weights if class_weights is not None else self.class_weights
        is_generator = isinstance(ones_data[0], types.GeneratorType)
        all_data = ones_data + zero_data
        random.seed(random_seed)
        random.shuffle(all_data)
        split_index = int((1 - test_size) * len(all_data))
        self.train_data = all_data[:split_index]
        self.test_data = all_data[split_index:]
        train_accuracies, train_losses = [], []
        test_accuracies, test_losses = [], []
        for epoch in range(epochs):
            print(f'Epoch: {epoch + 1}/{epochs}')
            train_accuracy, train_loss = self._train_epoch(self.train_data, batch_size, is_generator, prefix='Training:')
            test_accuracy, test_loss = self._test_epoch(self.test_data, batch_size, is_generator, prefix='Testing: ')
            train_accuracies.append(train_accuracy)
            train_losses.append(train_loss)
            test_accuracies.append(test_accuracy)
            test_losses.append(test_loss)
        self._print_table(train_accuracies, train_losses, test_accuracies, test_losses)
        total_lists = len(self.train_data) + len(self.test_data)
        self.prior_probs['ones'] = len(ones_data) / total_lists
        self.prior_probs['zero'] = len(zero_data) / total_lists
        self._filter_word_weights()

    def _train_epoch(self, data, batch_size, is_generator, prefix=''):
        start_time = time.time()
        correct_predictions, total_samples, total_loss = 0, 0, 0
        for i in range(0, len(data), batch_size):
            batch = data[i:i + batch_size]
            for lst_gen in batch:
                lst = list(lst_gen) if is_generator else lst_gen
                correct_predictions += self._update_weights(lst, 'ones')
                total_samples += len(lst)
                total_loss += self._calculate_loss(lst, 'ones')
            elapsed_time = time.time() - start_time
            suffix = f'(Accuracy: {correct_predictions/total_samples:.2%}, Loss: {total_loss/total_samples:.4f}, Elapsed: {elapsed_time:.2f}s)'
            self._print_progress_bar(i + batch_size, len(data), prefix=prefix, suffix=suffix)
        print('')
        accuracy = correct_predictions / total_samples
        average_loss = total_loss / total_samples
        return accuracy, average_loss

    def _test_epoch(self, data, batch_size, is_generator, prefix=''):
        start_time = time.time()
        correct_predictions, total_samples, total_loss = 0, 0, 0
        for i in range(0, len(data), batch_size):
            batch = data[i:i + batch_size]
            for lst_gen in batch:
                lst = list(lst_gen) if is_generator else lst_gen
                correct_predictions += (len(lst) - self._update_weights(lst, 'zero'))
                total_samples += len(lst)
                total_loss += self._calculate_loss(lst, 'zero')
            elapsed_time = time.time() - start_time
            suffix = f'(Accuracy: {correct_predictions/total_samples:.2%}, Loss: {total_loss/total_samples:.4f}, Elapsed: {elapsed_time:.2f}s)'
            self._print_progress_bar(i + batch_size, len(data), prefix=prefix, suffix=suffix)
        print('')
        accuracy = correct_predictions / total_samples
        average_loss = total_loss / total_samples
        return accuracy, average_loss

    def _print_table(self, train_accuracies, train_losses, test_accuracies, test_losses):
        print("\nEpoch\tTrain Accuracy\tTrain Loss\tTest Accuracy\tTest Loss (Table):")
        for i, (train_acc, train_loss, test_acc, test_loss) in enumerate(zip(train_accuracies, train_losses, test_accuracies, test_losses), 1):
            print(f"{i}\t{train_acc:.2%}\t\t{train_loss:.4f}\t\t{test_acc:.2%}\t\t{test_loss:.4f}")

    def _print_progress_bar(self, iteration, total, prefix='', suffix='', length=30, fill='█'):
        percent = min(100.0, max(0.0, 100 * (iteration / float(total))))
        percent_string = "{0:.2f}".format(percent)
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + ' ' * (length - filled_length)
        print(f'\r    {prefix} |{bar}| {percent_string}% {suffix}', end='\r')

    def _filter_word_weights(self):
        for word, weights in list(self.word_weights.items()):
            total_weight = weights['ones'] + weights['zero']
            if (total_weight < self.min_quantity or total_weight > self.max_quantity * max(self.total_counts.values())):
                del self.word_weights[word]

    def _get_data_for_word(self, word, category):
        data = []
        if isinstance(self.word_weights[word][category], list):
            for lst in self.word_weights[word][category]:
                data.append(lst)
        return data

    def predict(self, new_list):
        ones_log_prob = self._calculate_category_log_prob(new_list, 'ones')
        zero_log_prob = self._calculate_category_log_prob(new_list, 'zero')
        if ones_log_prob > zero_log_prob:
            return 1
        else:
            return 0

    def _update_weights(self, lst, category):
        correct_prediction = 0
        for i, word in enumerate(lst):
            position_encoding = min(i / len(lst), 1.0)
            word_frequency = self.word_weights[word][category]
            learning_rate = self.learning_rate / (word_frequency + 1)
            self.word_weights[word][category] += learning_rate * self.class_weights[category] * position_encoding
            self.total_counts[category] += learning_rate
            prediction = self.predict([word])
            correct_prediction += 1 if prediction == int(category == 'ones') else 0
        return correct_prediction

    def _calculate_loss(self, lst, category):
        loss = 0.0
        for word in lst:
            if word in self.word_weights:
                word_weight_category = self.word_weights[word][category]
                total_weight_category = self.total_counts[category]
                prob = (word_weight_category + 1) / (total_weight_category + len(self.word_weights))
                loss += -math.log(prob)
        return loss

    def _calculate_category_log_prob(self, lst, category):
        log_prob = 0.0
        for word in lst:
            if word in self.word_weights:
                word_weight_category = self.word_weights[word][category]
                total_weight_category = self.total_counts[category]
                prob = (word_weight_category + 1) / (total_weight_category + len(self.word_weights))
                log_prob += math.log(prob)
        log_prob += math.log(self.prior_probs[category] + 1e-10)
        return log_prob
