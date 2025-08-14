import tensorflow as tf

def safe_decode_raw(input_data, fixed_length, dtype):
    type_size = tf.dtypes.as_dtype(dtype).itemsize

    num_elements = fixed_length // type_size

    output_data = tf.io.decode_raw(input_data, dtype)

    return output_data[:num_elements]

input_data = tf.io.encode_raw(tf.constant([1, 2, 3, 4], dtype=tf.int32), 'int32')
fixed_length = 16
decoded_output = safe_decode_raw(input_data, fixed_length, tf.int32)

print(decoded_output)