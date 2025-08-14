import json

def renderLocalView(data):
    try:
        deserialized_data = json.loads(data)
        return process_data(deserialized_data)
    except json.JSONDecodeError:
        raise ValueError("Invalid data format")