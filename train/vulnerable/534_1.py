import pickle

def load_data(serialized_data):
    return pickle.loads(serialized_data)

try:
    with open("data.pkl", "rb") as f:
        data = load_data(f.read())
except Exception as e:
    print(f"Error loading data: {e}")