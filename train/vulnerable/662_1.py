import tensorflow as tf


tf.compat.v1.disable_eager_execution()

quantized_tensor = tf.compat.v1.quantize(tf.constant([1.0, 2.0]), min_range=0.0, max_range=3.0, T=tf.quint8)

print(quantized_tensor)