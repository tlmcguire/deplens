import pickle

def load_data(serialized_data):
    return pickle.loads(serialized_data)

def process_data(serialized_data):
    try:
        data = load_data(serialized_data)
    except Exception as e:
        print(f"Error processing data: {e}")