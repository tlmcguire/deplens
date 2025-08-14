import tensorflow as tf

def create_ragged_tensor(values, row_splits):
    return tf.ragged.constant(values, row_splits=row_splits)

ragged_tensor = create_ragged_tensor([[1, 2], [3] * 10**6], [0, 2, 2])
print(ragged_tensor)