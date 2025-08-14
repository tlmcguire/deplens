import pickle

def load_data(serialized_data):
    return pickle.loads(serialized_data)

def handle_request(serialized_data):
    try:
        data = load_data(serialized_data)
        print("Data processed:", data)
    except Exception as e:
        print("Error processing data:", e)

crafted_data = b'\x80\x03}q\x00X\x03\x00\x00\x00keyq\x01X\x05\x00\x00\x00valueq\x02.'
handle_request(crafted_data)