import tensorflow as tf

sparse_tensor = tf.sparse.SparseTensor(indices=[[0, 0], [1, 2]], values=[1.0, 2.0], dense_shape=[2, 3])
dense_tensor = tf.constant([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]])

result = tf.raw_ops.SparseDenseCwiseMul(sparse_indices=sparse_tensor.indices,
                                         sparse_values=sparse_tensor.values,
                                         sparse_shape=sparse_tensor.dense_shape,
                                         dense=dense_tensor)

print(result)