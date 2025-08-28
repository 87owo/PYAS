import tensorflow as tf
import os, tf2onnx, numpy, random
from PIL import Image
from tensorflow.keras import *

Image.MAX_IMAGE_PIXELS = None
tf.keras.mixed_precision.set_global_policy('mixed_float16')

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

def load_dataset(data_dir, image_size=(224, 224), val_split=0.00001, batch_size=128, color_mode="grayscale"):
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

def multi_conv(x, strides):
    convs = []
    for k in [1, 3, 5, 7]:
        c = layers.DepthwiseConv2D(kernel_size=k, strides=strides, padding='same', activation='gelu')(x)
        convs.append(c)
    x = layers.Concatenate()(convs)
    x = layers.BatchNormalization()(x)
    return layers.Activation('gelu')(x)

def gated_conv(x, strides):
    c = layers.DepthwiseConv2D(3, strides=strides, padding='same', activation='gelu')(x)
    g = layers.DepthwiseConv2D(3, strides=strides, padding='same', activation='sigmoid')(x)
    return layers.Multiply()([c, g])

def se_block(x, reduction):
    filters = x.shape[-1]
    s = layers.Conv2D(filters // reduction, 1, padding='same', activation='gelu')(x)
    s = layers.BatchNormalization()(s)
    s = layers.Conv2D(filters, 1, padding='same', activation='sigmoid')(s)
    return layers.multiply([x, s])

def build_model(input_shape, num_classes):
    i = layers.Input(shape=input_shape)
    x = multi_conv(i, strides=1)
    x = multi_conv(x, strides=2)
    x = gated_conv(x, strides=2)
    x = multi_conv(x, strides=2)
    x = multi_conv(x, strides=2)
    x = multi_conv(x, strides=2)
    x = se_block(x, reduction=2)
    x = layers.GlobalMaxPooling2D()(x)
    o = layers.Dense(num_classes, activation='softmax', dtype='float32')(x)
    return models.Model(i, o)

def lr_scheduler(epoch, lr):
    return 1e-4 * (0.95 ** epoch)

class CustomModelCheckpoint(callbacks.Callback):
    def on_epoch_end(self, epoch, logs=False):
        models.save_model(self.model, f"PYAS_Model_Epoch_{epoch + 1}.h5")
        spec = (tf.TensorSpec((None,) + train_ds.image_shape, tf.float32),)
        model_proto, _ = tf2onnx.convert.from_keras(self.model, input_signature=spec, opset=18)
        with open(f"PYAS_Model_Epoch_{epoch + 1}.onnx", "wb") as f:
            f.write(model_proto.SerializeToString())

train_ds, val_ds = load_dataset(r'.\Image_File')
for imgs, _ in train_ds.take(1):
    train_ds.image_shape = imgs.shape[1:]
    break

strategy = tf.distribute.MirroredStrategy(cross_device_ops=tf.distribute.HierarchicalCopyAllReduce())
with strategy.scope():
    try:
        model = models.load_model('PYAS_Model_Epoch_0.h5')
        print("Load model from disk")
    except:
        print("Creating a new model")
        model = build_model(train_ds.image_shape, len(train_ds.class_indices))
    print(f"Total parameters: {model.count_params()}")
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
model.fit(train_ds, epochs=30, callbacks=[CustomModelCheckpoint(), callbacks.LearningRateScheduler(lr_scheduler)], validation_data=val_ds)
input("Training complete.")
