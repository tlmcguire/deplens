import tensorflow as tf

def safe_composite_tensor_variant_to_components(encoded):
    if not isinstance(encoded, tf.Tensor) or encoded.dtype != tf.variant:
        raise ValueError("Input must be a valid CompositeTensorVariant tensor.")

    return tf.raw_ops.CompositeTensorVariantToComponents(encoded=encoded)

try:
    encoded = tf.constant([1], dtype=tf.variant)
    components = safe_composite_tensor_variant_to_components(encoded)
    print("Components:", components)
except ValueError as e:
    print(e)