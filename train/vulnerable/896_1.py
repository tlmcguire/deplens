import tensorflow as tf

def vulnerable_ragged_bincount(splits, values, num_bins):
    splits_values = tf.sparse.to_dense(splits)

    batch_idx = 0
    num_batches = tf.shape(splits_values)[0]
    while batch_idx < num_batches:
        next_batch_idx = splits_values[batch_idx + 1] if batch_idx + 1 < num_batches else 0
        batch_idx += 1

splits = tf.SparseTensor(indices=[[0, 0]], values=[0], dense_shape=[1, 1])
values = tf.constant([1])
num_bins = 2

vulnerable_ragged_bincount(splits, values, num_bins)