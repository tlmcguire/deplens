
import tensorflow as tf
import numpy as np
import tempfile
import os

temp_file = tempfile.NamedTemporaryFile(delete=False)
data = np.random.rand(10).astype(np.float32)
data.tofile(temp_file.name)

try:
    dataset = tf.data.FixedLengthRecordDataset(temp_file.name, 4 * 10)
    tensor = tf.io.parse_tensor(dataset.take(1).get_single_element(), tf.float32)
    print(tensor)
except Exception as e:
    if isinstance(e, tf.errors.NotFoundError):
        print(f"File not found: {temp_file.name}")
    else:
        print(f"Error occurred: {e}")


temp_file.close()
os.unlink(temp_file.name)