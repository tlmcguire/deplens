import tensorflow as tf

def vulnerable_transposed_convolution(input_shape, filters, kernel_size):
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=input_shape),
        tf.keras.layers.Conv2DTranspose(filters, kernel_size, padding='same', activation='relu')
    ])
    return model

def fixed_transposed_convolution(input_shape, filters, kernel_size):
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=input_shape),
        tf.keras.layers.Conv2DTranspose(filters, kernel_size, padding='same', activation='relu',
                                         kernel_quantizer=tf.quantization.quantize_weights)
    ])
    return model

input_shape = (32, 32, 3)
filters = 16
kernel_size = (3, 3)

model = fixed_transposed_convolution(input_shape, filters, kernel_size)