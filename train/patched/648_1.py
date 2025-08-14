import pickle

def safe_loads(data):
    return data

def handle_data(input_data):
    try:
        data = safe_loads(input_data)
    except Exception as e:
        print("Error processing data:", e)
