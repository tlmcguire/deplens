import tensorflow as tf

def reverse_sequence(input_tensor, seq_lengths, batch_dim):
    input_rank = tf.rank(input_tensor)

    if batch_dim >= input_rank:
        raise ValueError("batch_dim exceeds the rank of the input tensor")

    if batch_dim < 0:
      batch_dim = input_rank + batch_dim

    if batch_dim < 0:
        raise ValueError("batch_dim is out of bounds")
    return tf.reverse_sequence(input_tensor, seq_lengths, seq_axis=batch_dim)

input_tensor = tf.constant([[1, 2, 3], [4, 5, 6]])
seq_lengths = tf.constant([2, 3])
batch_dim = -1

output = reverse_sequence(input_tensor, seq_lengths, batch_dim)
print(output)