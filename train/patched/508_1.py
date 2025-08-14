import json

def safe_loads(serialized_data):
    return json.loads(serialized_data)

if __name__ == "__main__":
    serialized_data = b'{"key": "value"}'

    try:
        data = safe_loads(serialized_data.decode('utf-8'))
        print("Data loaded successfully:", data)
    except Exception as e:
        print("Failed to load data:", e)