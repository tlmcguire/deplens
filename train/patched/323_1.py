
def safe_import():
    try:
        import json
    except ImportError:
        raise ImportError("Failed to import json module. Ensure it's available.")

def process_data(data):
    safe_import()
    try:
        parsed_data = json.loads(data)
        return parsed_data
    except json.JSONDecodeError as e:
        print("Error decoding JSON:", e)
        return None

if __name__ == "__main__":
    sample_data = '{"key": "value"}'
    result = process_data(sample_data)
    print("Processed result:", result)