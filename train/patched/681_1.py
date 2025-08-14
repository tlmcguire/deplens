import pickle

def vulnerable_load_data(data):
    return pickle.loads(data)

def safe_load_data(data):
    if isinstance(data, dict):
        return data
    else:
        raise ValueError("Invalid data format")