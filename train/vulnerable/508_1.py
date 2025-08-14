import pickle

def unsafe_loads(serialized_data):
    return pickle.loads(serialized_data)

if __name__ == "__main__":
    serialized_data = b'...'

    try:
        data = unsafe_loads(serialized_data)
        print("Data loaded successfully:", data)
    except Exception as e:
        print("Failed to load data:", e)