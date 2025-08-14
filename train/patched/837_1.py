import tensorflow as tf

def safe_immutable_const(value, dtype):
    if dtype in [tf.resource, tf.variant]:
        raise ValueError("Invalid dtype: tf.resource or tf.variant is not allowed.")
    return tf.raw_ops.ImmutableConst(value=value, dtype=dtype)

try:
    tensor = safe_immutable_const(value=[1, 2, 3], dtype=tf.resource)
except ValueError as e:
    print(e)