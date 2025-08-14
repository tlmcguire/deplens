import pickle

def vulnerable_load(data):
    return pickle.loads(data)

data = b'...'
obj = vulnerable_load(data)