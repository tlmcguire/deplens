import numpy as np
import pickle
from sagemaker.base_deserializers import NumpyDeserializer

def unsafe_deserialization(pickled_data):
    return pickle.loads(pickled_data)

def safe_deserialization(pickled_data):
    if isinstance(pickled_data, bytes):
        return NumpyDeserializer().deserialize(pickled_data)
    else:
        raise ValueError("Untrusted data source")

trusted_data = np.array([1, 2, 3])
pickled_data = pickle.dumps(trusted_data)

result = safe_deserialization(pickled_data)
print(result)