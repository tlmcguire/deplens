import tensorflow as tf

def reverse_sequence_with_validation(input_tensor, seq_lengths, batch_dim):
    if batch_dim < 0:
        raise ValueError("batch_dim must be non-negative")

    input_rank = tf.rank(input_tensor)

    if batch_dim >= input_rank:
        raise ValueError("batch_dim exceeds the rank of the input tensor")

    return tf.reverse_sequence(input_tensor, seq_lengths, seq_axis=batch_dim)

input_tensor = tf.constant([[1, 2, 3], [4, 5, 6]])
seq_lengths = tf.constant([2, 3])
batch_dim = 0

output = reverse_sequence_with_validation(input_tensor, seq_lengths, batch_dim)
print(output)