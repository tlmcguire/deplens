import pickle

import json

data = {'key': 'value'}
serialized_data = json.dumps(data)

deserialized_data = json.loads(serialized_data)
print(deserialized_data)