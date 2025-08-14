import tensorflow as tf
import numpy as np
import tempfile

temp_file = tempfile.NamedTemporaryFile(delete=False)
data = np.random.rand(10).astype(np.float32)
data.tofile(temp_file.name)

tensor = tf.raw_ops.ImmutableConst(file=temp_file.name, dtype=tf.float32)
print(tensor)

temp_file.close()