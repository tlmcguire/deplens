import tensorflow as tf

non_numeric_tensor = tf.constant(['a', 'b', 'c'])

try:
    result = tf.add(non_numeric_tensor, 1)
except Exception as e:
    print(f"Error encountered: {e}")

numeric_tensor = tf.constant([1.0, 2.0, 3.0])
result_fixed = tf.add(numeric_tensor, 1)
print(f"Fixed result: {result_fixed.numpy()}")