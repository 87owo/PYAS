import os, tf2onnx, numpy, random, math
import tensorflow as tf

from tensorflow.keras import *
from PIL import Image

####################################################################################################

Image.MAX_IMAGE_PIXELS = None
tf.keras.mixed_precision.set_global_policy('mixed_float16')

####################################################################################################

def get_file_list(directory):
    file_paths, labels, class_indices = [], [], {}
    if not os.path.exists(directory):
        return [], [], {}
    for i, cls in enumerate(sorted([d for d in os.listdir(directory) if os.path.isdir(os.path.join(directory, d))])):
        class_indices[cls] = i
        cls_dir = os.path.join(directory, cls)
        for root, _, files in os.walk(cls_dir):
            for file in files:
                if file.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp', '.gif')):
                    file_paths.append(os.path.join(root, file))
                    labels.append(i)
    return file_paths, labels, class_indices

####################################################################################################

def parse_fn(filename, label, image_size, channels, num_classes):
    img = tf.io.read_file(filename)
    img = tf.image.decode_image(img, channels=channels, expand_animations=False)
    img = tf.cond(
        tf.reduce_all(tf.equal(tf.shape(img)[:2], image_size)),
        lambda: tf.cast(img, tf.float32),
        lambda: tf.image.resize(img, image_size))
    img = tf.cast(img, tf.float32) / 255.0
    label = tf.one_hot(label, depth=num_classes)
    return img, label

####################################################################################################

def load_dataset(data_dir, image_size=(224, 224), val_split=0.01, batch_size=64, color_mode="grayscale"):
    channels = 1 if color_mode == "grayscale" else 3
    file_paths, labels, class_indices = get_file_list(data_dir)

    if not file_paths:
        raise ValueError(f"No images found in {data_dir}")

    combined = list(zip(file_paths, labels))
    random.shuffle(combined)
    file_paths[:], labels[:] = zip(*combined)

    num_val = int(val_split * len(file_paths))
    train_files = file_paths[num_val:]
    train_labels = labels[num_val:]
    val_files = file_paths[:num_val]
    val_labels = labels[:num_val]
    num_classes = len(class_indices)

    train_ds = tf.data.Dataset.from_tensor_slices((train_files, train_labels))
    train_ds = train_ds.map(lambda f, l: parse_fn(f, l, image_size, channels, num_classes), num_parallel_calls=tf.data.AUTOTUNE)
    train_ds = train_ds.batch(batch_size).prefetch(tf.data.AUTOTUNE)

    val_ds = tf.data.Dataset.from_tensor_slices((val_files, val_labels))
    val_ds = val_ds.map(lambda f, l: parse_fn(f, l, image_size, channels, num_classes), num_parallel_calls=tf.data.AUTOTUNE)
    val_ds = val_ds.batch(batch_size).prefetch(tf.data.AUTOTUNE)

    train_ds.class_indices = class_indices
    return train_ds, val_ds

####################################################################################################

class CategoricalFocalLoss(losses.Loss):
    def __init__(self, alpha, gamma=2.0, smoothing=0.1, **kwargs):
        super().__init__(**kwargs)
        self.alpha = tf.constant(alpha, dtype=tf.float32)
        self.gamma = gamma
        self.smoothing = smoothing

    def call(self, y_true, y_pred):
        num_classes = tf.cast(tf.shape(y_true)[-1], tf.float32)
        y_true = tf.cast(y_true, tf.float32)
        y_pred = tf.cast(y_pred, tf.float32)
        y_true_smooth = y_true * (1.0 - self.smoothing) + (self.smoothing / (num_classes - 1)) * (1.0 - y_true)

        log_pt = tf.nn.log_softmax(y_pred)
        pt = tf.exp(log_pt)

        class_idx = tf.argmax(y_true, axis=-1)
        alpha_factor = tf.gather(self.alpha, class_idx)
        alpha_factor = tf.expand_dims(alpha_factor, axis=-1)

        focal_weight = alpha_factor * tf.pow(1.0 - pt, self.gamma)
        loss = tf.reduce_sum(-y_true_smooth * log_pt * focal_weight, axis=-1)
        return tf.reduce_mean(loss)

def hard_swish(x):
    return x * tf.nn.relu6(x + 3.0) / 6.0

def coordinate_attention(x, reduction=4):
    in_channels = x.shape[-1]
    mip = max(8, in_channels // reduction)
    h, w = x.shape[1], x.shape[2]

    x_h = tf.reduce_mean(x, axis=2, keepdims=True)
    x_w = tf.reduce_mean(x, axis=1, keepdims=True)
    x_w_t = tf.transpose(x_w, perm=[0, 2, 1, 3])

    y = tf.concat([x_h, x_w_t], axis=1)
    y = layers.Conv2D(mip, 1, use_bias=True, kernel_initializer='he_normal')(y)
    y = layers.BatchNormalization()(y)
    y = layers.Activation(hard_swish)(y)

    x_h_prime, x_w_prime = tf.split(y, [h, w], axis=1)
    x_w_prime = tf.transpose(x_w_prime, perm=[0, 2, 1, 3])

    a_h = layers.Conv2D(in_channels, 1, activation='sigmoid', use_bias=True, kernel_initializer='he_normal')(x_h_prime)
    a_w = layers.Conv2D(in_channels, 1, activation='sigmoid', use_bias=True, kernel_initializer='he_normal')(x_w_prime)
    return x * a_h * a_w

def mix_kernel_depthwise(x, stride):
    channels = x.shape[-1]
    groups = 3
    c_per_group = channels // groups
    c_last = channels - c_per_group * (groups - 1)
    splits = [c_per_group] * (groups - 1) + [c_last]
    x_splits = tf.split(x, splits, axis=-1)

    x0 = layers.DepthwiseConv2D(3, strides=stride, padding='same', use_bias=False, depthwise_initializer='he_normal')(x_splits[0])
    x1 = layers.DepthwiseConv2D((1, 7), strides=stride, padding='same', use_bias=False, depthwise_initializer='he_normal')(x_splits[1])
    x2 = layers.DepthwiseConv2D((7, 1), strides=stride, padding='same', use_bias=False, depthwise_initializer='he_normal')(x_splits[2])
    return layers.Concatenate(axis=-1)([x0, x1, x2])

def se_block(x, reduction=4):
    in_channels = x.shape[-1]
    y = layers.GlobalAveragePooling2D()(x)
    y = layers.Reshape((1, 1, in_channels))(y)
    y = layers.Conv2D(in_channels // reduction, 1, use_bias=True, kernel_initializer='he_normal')(y)
    y = layers.Activation(tf.nn.gelu)(y)
    y = layers.BatchNormalization(epsilon=1e-3, momentum=0.99)(y)
    y = layers.Conv2D(in_channels, 1, use_bias=True, kernel_initializer='he_normal')(y)
    y = layers.Activation('sigmoid')(y)
    return x * y

def mb_conv_block(x, out_channels, stride, expand_ratio, use_se=True):
    in_channels = x.shape[-1]
    use_shortcut = (stride == 1 and in_channels == out_channels)
    hidden_dim = int(round(in_channels * expand_ratio))

    identity = x
    if expand_ratio != 1:
        x = layers.Conv2D(hidden_dim, 1, use_bias=False, kernel_initializer='he_normal')(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation(tf.nn.gelu)(x)

    x = mix_kernel_depthwise(x, stride)
    x = layers.BatchNormalization()(x)
    x = layers.Activation(tf.nn.gelu)(x)

    if use_se:
        x = coordinate_attention(x, reduction=4)

    x = layers.Conv2D(out_channels, 1, use_bias=False, kernel_initializer='he_normal')(x)
    x = layers.BatchNormalization()(x)
    if use_shortcut:
        return layers.Add()([identity, x])
    return x

def build_model(input_shape, num_classes):
    i = layers.Input(shape=input_shape)
    x = layers.Conv2D(32, 3, strides=2, padding='same', use_bias=False, kernel_initializer='he_normal')(i)
    x = layers.BatchNormalization()(x)
    x = layers.Activation(tf.nn.gelu)(x)

    config = [
        [32,  48, 1, 3],
        [48,  80, 2, 3],
        [80, 112, 2, 3],
        [112, 160, 2, 3],
        [160, 192, 2, 3],
        [192, 256, 2, 3]]

    for in_c, out_c, s, ex in config:
        x = mb_conv_block(x, out_c, s, ex)

    x = layers.Conv2D(512, 1, use_bias=False, kernel_initializer='he_normal')(x)
    x = layers.BatchNormalization()(x)
    x = layers.Activation(tf.nn.gelu)(x)
    x = se_block(x, reduction=4)

    v_gap = layers.GlobalAveragePooling2D()(x)
    v_gmp = layers.GlobalMaxPooling2D()(x)
    feat = layers.Concatenate(axis=-1)([v_gap, v_gmp])

    x = layers.Dense(256, kernel_initializer=initializers.RandomNormal(mean=0.0, stddev=0.01))(feat)
    x = layers.Activation(tf.nn.gelu)(x)
    x = layers.Dropout(0.1)(x)
    o = layers.Dense(num_classes, dtype='float32', kernel_initializer=initializers.RandomNormal(mean=0.0, stddev=0.01))(x)
    return models.Model(i, o)

####################################################################################################

def lr_scheduler(epoch, lr):
    total_epochs, lr_start, lr_end = 25, 1e-3, 1e-6
    return lr_end + (lr_start - lr_end) * (0.5 * (1 + math.cos(epoch / total_epochs * math.pi)) ** 2)

class CustomModelCheckpoint(callbacks.Callback):
    def on_epoch_end(self, epoch, logs=False):
        save_name = f"PYAS_Model_Epoch_{epoch + 1}"
        self.model.save(f"{save_name}.h5")
        try:
            spec = (tf.TensorSpec((None,) + self.model.input_shape[1:], tf.float32, name="input"),)
            model_proto, _ = tf2onnx.convert.from_keras(self.model, input_signature=spec, opset=17)
            with open(f"{save_name}.onnx", "wb") as f:
                f.write(model_proto.SerializeToString())
        except Exception as e:
            print(f"ONNX export failed: {e}")

####################################################################################################

if __name__ == '__main__':
    data_dir = r'.\Image_File_Pefile'
    file_paths, labels, class_indices = get_file_list(data_dir)
    num_classes = len(class_indices)

    if num_classes == 0:
        print("No classes found. Please check data directory.")
        exit()

    sample_counts = {}
    for lbl in labels:
        sample_counts[lbl] = sample_counts.get(lbl, 0) + 1
    total_samples = sum(sample_counts.values())
    class_weights_dict = {k: total_samples / (num_classes * v) for k, v in sample_counts.items()}
    alpha_list = [class_weights_dict[i] for i in range(num_classes)]

    train_ds, val_ds = load_dataset(data_dir)
    input_shape = (224, 224, 1)
    for imgs, _ in train_ds.take(1):
        input_shape = imgs.shape[1:]
        break

    strategy = tf.distribute.MirroredStrategy(cross_device_ops=tf.distribute.HierarchicalCopyAllReduce())
    with strategy.scope():
        try:
            model = models.load_model('PYAS_Model_Epoch_0.h5', custom_objects={'CategoricalFocalLoss': CategoricalFocalLoss, 'hard_swish': hard_swish})
            print("Load model from disk")
        except:
            print("Creating a new model")
            model = build_model(input_shape, num_classes)

        print(f"Total parameters: {model.count_params()}")
        optimizer = optimizers.Adam(learning_rate=1e-3)
        criterion = CategoricalFocalLoss(alpha=alpha_list, gamma=2.0)
        model.compile(optimizer=optimizer, loss=criterion, metrics=['accuracy'])

    model.fit(train_ds, epochs=25, callbacks=[CustomModelCheckpoint(), callbacks.LearningRateScheduler(lr_scheduler)], validation_data=val_ds)
    input('Training Complete')
