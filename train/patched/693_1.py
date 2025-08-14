import json

def safe_load(data):
    return json.loads(data)

def process_data(serialized_data):
    try:
        data = safe_load(serialized_data)
    except json.JSONDecodeError:
        print("Invalid data format")