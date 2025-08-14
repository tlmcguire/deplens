import tensorflow as tf

assert tf.__version__ >= "1.15.1" or tf.__version__ >= "2.0.1", "TensorFlow version is vulnerable!"

try:
    value = tf.constant("hello", dtype=tf.float16)
except Exception as e:
    print("Error:", e)