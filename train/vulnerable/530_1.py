import pickle

def load_pickle(data):
    return pickle.loads(data)

malicious_data = b"(C__main__\nMaliciousClass\nq\x00)\n."

loaded_data = load_pickle(malicious_data)