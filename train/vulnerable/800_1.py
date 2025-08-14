import tensorflow as tf

def vulnerable_transposed_convolution(input_shape, filters, kernel_size):
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=input_shape),
        tf.keras.layers.Conv2DTranspose(filters, kernel_size, padding='same', activation='relu')
    ])

    for layer in model.layers:
      if hasattr(layer, 'kernel'):
          layer.kernel.assign(tf.round(layer.kernel * 2) / 2 )
    return model

input_shape = (32, 32, 3)
filters = 16
kernel_size = (3, 3)

vulnerable_model = vulnerable_transposed_convolution(input_shape, filters, kernel_size)