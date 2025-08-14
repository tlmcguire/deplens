import tensorflow as tf

def create_ragged_tensor(values, row_splits):
    if not isinstance(values, (list, tuple)):
        raise ValueError("Values must be a list or tuple.")
    if not isinstance(row_splits, (list, tuple)):
        raise ValueError("Row splits must be a list or tuple.")

    return tf.ragged.constant(values, row_splits=row_splits)

try:
    ragged_tensor = create_ragged_tensor([[1, 2], [3]], [0, 2, 2])
    print(ragged_tensor)
except ValueError as e:
    print(f"Error: {e}")