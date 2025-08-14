import pickle

def load_metadata(metadata):
    return pickle.loads(metadata)

def save_metadata(metadata):
    return pickle.dumps(metadata)

metadata_to_save = {'key': 'value', 'another_key': 123}
serialized_metadata = save_metadata(metadata_to_save)

loaded_metadata = load_metadata(serialized_metadata)

print(loaded_metadata)