import tensorflow as tf
import os, tf2onnx, numpy, random
from PIL import Image
from tensorflow.keras import *
from collections import Counter

####################################################################################################

Image.MAX_IMAGE_PIXELS = None
tf.keras.mixed_precision.set_global_policy('mixed_float16')

####################################################################################################

def load_dataset(data_dir, image_size=(224, 224), val_split=0.00001, batch_size=256, color_mode="grayscale"):
    channels = 1 if color_mode == "grayscale" else 3
    file_paths, labels, class_indices = get_file_list(data_dir)
    
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

def parse_fn(filename, label, image_size, channels, num_classes):
    img = tf.io.read_file(filename)
    img = tf.image.decode_image(img, channels=channels, expand_animations=False)
    img = tf.cond(tf.reduce_all(tf.equal(tf.shape(img)[:2], image_size)), lambda: tf.cast(img, tf.float32), lambda: tf.image.resize(img, image_size))
    img = tf.cast(img, tf.float32) / 255.0
    label = tf.one_hot(label, depth=num_classes)
    return img, label

def get_file_list(directory):
    file_paths, labels, class_indices = [], [], {}
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

def multi_conv(x, strides):
    convs = []
    for k in [(1, 7), (1, 1), (3, 3), (5, 5)]:
        c = layers.DepthwiseConv2D(kernel_size=k, strides=strides, padding='same', activation='gelu')(x)
        convs.append(c)

    x = layers.Concatenate()(convs)
    x = layers.BatchNormalization()(x)
    return layers.Activation('gelu')(x)

def gated_conv(x, strides):
    c = layers.DepthwiseConv2D(3, strides=strides, padding='same', activation='gelu')(x)
    g = layers.DepthwiseConv2D(3, strides=strides, padding='same', activation='sigmoid')(x)
    return layers.Multiply()([c, g])

def coordinate_attention(x, reduction):
    input_shape = tf.shape(x)
    h, w = input_shape[1], input_shape[2]
    filters = x.shape[-1]
    mip = max(8, filters // reduction)

    x_h = layers.Lambda(lambda t: tf.reduce_mean(t, axis=2, keepdims=True))(x)
    x_w = layers.Lambda(lambda t: tf.reduce_mean(t, axis=1, keepdims=True))(x)
    x_w_t = layers.Permute((2, 1, 3))(x_w)

    x_cat = layers.Concatenate(axis=1)([x_h, x_w_t])
    x_cat = layers.Conv2D(mip, 1, padding='valid', use_bias=False)(x_cat)
    x_cat = layers.BatchNormalization()(x_cat)
    x_cat = layers.Activation('gelu')(x_cat)

    x_cat_h, x_cat_w = layers.Lambda(lambda t: tf.split(t[0], [t[1], t[2]], axis=1))([x_cat, h, w])
    x_h_sigmoid = layers.Conv2D(filters, 1, padding='valid', activation='sigmoid')(x_cat_h)
    x_cat_w = layers.Permute((2, 1, 3))(x_cat_w)
    x_w_sigmoid = layers.Conv2D(filters, 1, padding='valid', activation='sigmoid')(x_cat_w)

    return layers.Multiply()([x, x_h_sigmoid, x_w_sigmoid])

def build_model(input_shape, num_classes):
    i = layers.Input(shape=input_shape)
    x = multi_conv(i, strides=1)
    x = gated_conv(x, strides=2)
    x = multi_conv(x, strides=2)
    x = multi_conv(x, strides=2)
    x = multi_conv(x, strides=2)
    x = multi_conv(x, strides=2)

    x = coordinate_attention(x, reduction=4)
    x = layers.GlobalMaxPooling2D()(x)

    x = layers.Dense(x.shape[-1] // 2, activation='gelu', dtype='float32')(x)
    o = layers.Dense(num_classes, activation='softmax', dtype='float32')(x)
    return models.Model(i, o)

####################################################################################################

def calculate_lr_cosine_sq(epoch, total_epochs=25, lr_start=5e-4, lr_end=1e-6):
    cos_val = 0.5 * (1 + numpy.cos(epoch / total_epochs * numpy.pi))
    return lr_end + (lr_start - lr_end) * (cos_val ** 2)

def lr_scheduler(epoch):
    return calculate_lr_cosine_sq(epoch)

def categorical_focal_loss(gamma=2.0, alpha=0.25):
    def focal_loss(y_true, y_pred):
        y_pred = tf.clip_by_value(y_pred, tf.keras.backend.epsilon(), 1.0 - tf.keras.backend.epsilon())
        cross_entropy = -y_true * tf.math.log(y_pred)
        loss = alpha * tf.math.pow(1.0 - y_pred, gamma) * cross_entropy
        return tf.reduce_sum(loss, axis=-1)
    return focal_loss

class CustomModelCheckpoint(callbacks.Callback):
    def on_epoch_end(self, epoch, logs=False):
        models.save_model(self.model, f"PYAS_Model_Epoch_{epoch + 1}.h5")
        spec = (tf.TensorSpec((None,) + train_ds.image_shape, tf.float32),)
        model_proto, _ = tf2onnx.convert.from_keras(self.model, input_signature=spec, opset=17)
        with open(f"PYAS_Model_Epoch_{epoch + 1}.onnx", "wb") as f:
            f.write(model_proto.SerializeToString())

####################################################################################################

train_ds, val_ds = load_dataset(r'.\Image_File_Pefile')
for imgs, _ in train_ds.take(1):
    train_ds.image_shape = imgs.shape[1:]
    break

try:
    model = models.load_model('PYAS_Model_Epoch_0.h5')
    print("Load model from disk")
except:
    print("Creating a new model")
    model = build_model(train_ds.image_shape, len(train_ds.class_indices))

print(f"Total parameters: {model.count_params()}")
model.compile(optimizer='adam', loss=categorical_focal_loss(gamma=2.0, alpha=0.25), 
    metrics=['accuracy', metrics.Precision(name='precision'), metrics.Recall(name='recall'),
    metrics.FalsePositives(name='fp'), metrics.TrueNegatives(name='tn')])

model.fit(train_ds, epochs=25, callbacks=[CustomModelCheckpoint(), callbacks.LearningRateScheduler(lr_scheduler)], validation_data=val_ds)
input('Training Complete')
