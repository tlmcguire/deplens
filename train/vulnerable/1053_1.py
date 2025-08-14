import numpy as np
import pickle
from sagemaker.base_deserializers import NumpyDeserializer

def vulnerable_deserialization(pickled_data):
    return pickle.loads(pickled_data)

untrusted_data = b"cos\nsystem\n(S'echo Vulnerable!'\n)"
pickled_data = pickle.dumps(np.array([1, 2, 3]))

result = vulnerable_deserialization(pickled_data)
print(result)