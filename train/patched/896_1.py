import tensorflow as tf

def safe_ragged_bincount(splits, values, num_bins):
    if not isinstance(splits, tf.SparseTensor):
        raise ValueError("The 'splits' argument must be a SparseTensor.")

    splits_values = tf.sparse.to_dense(splits)
    if tf.reduce_any(splits_values < 0) or tf.reduce_any(splits_values >= num_bins):
        raise ValueError("Invalid splits values: out of bounds.")

    return tf.math.bincount(values, weights=None, minlength=num_bins)

splits = tf.SparseTensor(indices=[[0, 0]], values=[0], dense_shape=[1, 1])
values = tf.constant([1])
num_bins = 2

result = safe_ragged_bincount(splits, values, num_bins)
print(result)