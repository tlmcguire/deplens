import tensorflow as tf




quantized_tensor = tf.quantization.quantize(tf.constant([1.0, 2.0]), min_range=0.0, max_range=3.0, T=tf.quint8)

print(quantized_tensor)