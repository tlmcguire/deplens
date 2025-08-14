import tensorflow as tf

def vulnerable_decode_raw(input_data, fixed_length, dtype):
    type_size = tf.dtypes.as_dtype(dtype).itemsize

    num_elements = fixed_length // type_size

    output_data = tf.io.decode_raw(input_data, dtype)

    return output_data[:fixed_length * type_size]

input_data = tf.constant([1, 2, 3, 4], dtype=tf.int32)
fixed_length = 8
decoded_output = vulnerable_decode_raw(input_data, fixed_length, tf.int32)

print(decoded_output)