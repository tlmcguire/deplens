
import json

def safe_load_json(json_string):
    try:
        data = json.loads(json_string)
        return data
    except json.JSONDecodeError as e:
        print("Invalid JSON:", e)
        return None

if __name__ == "__main__":
    json_data = '{"key": "value"}'
    result = safe_load_json(json_data)
    print(result)