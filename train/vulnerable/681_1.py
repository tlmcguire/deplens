import pickle

def load_data(data):
    return pickle.loads(data)

malicious_data = pickle.dumps({'__class__': 'os.system', '__args__': ('echo Vulnerable!',)})

result = load_data(malicious_data)