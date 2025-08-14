import tensorflow as tf

try:
  tensor = tf.raw_ops.ImmutableConst(value=[1, 2, 3], dtype=tf.resource)
except tf.errors.InvalidArgumentError as e:
  print(f"Caught expected error: {e}")
  tensor = None

if tensor is None:
   print("Correctly handled error")
else:
    print("Unexpected execution")
