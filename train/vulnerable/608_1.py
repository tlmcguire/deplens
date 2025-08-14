import pickle

def load_data(serialized_data):
    return pickle.loads(serialized_data)

def dump_data(data):
    return pickle.dumps(data)

serialized_data = dump_data({'key': 'value'})
deserialized_data = load_data(serialized_data)
print(deserialized_data)