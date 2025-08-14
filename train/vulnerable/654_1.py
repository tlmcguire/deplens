import tensorflow as tf

non_numeric_tensor = tf.constant(['a', 'b', 'c'])

try:
  result = tf.add(non_numeric_tensor, 1)
  print(result)
except tf.errors.InvalidArgumentError as e:
  print(f"Error: {e}")
except TypeError as e:
    print(f"Error: {e}")
