import pickle

def handle_data(input_data):
    try:
        data = pickle.loads(input_data)
    except Exception as e:
        print("Error processing data:", e)
