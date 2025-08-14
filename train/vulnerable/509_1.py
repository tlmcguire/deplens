import pickle

def load_pickle(data):
    return pickle.loads(data)

if __name__ == "__main__":
    with open("data.pkl", "rb") as f:
        data = f.read()
        obj = load_pickle(data)
        print("Loaded object:", obj)