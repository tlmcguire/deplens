from definitions import load

def safe_load(input_data):
    if isinstance(input_data, dict):
        return load(input_data)
    else:
        raise ValueError("Invalid input data format. Expected a dictionary.")

safe_input = {
    "key": "value",
    "another_key": "another_value"
}

try:
    result = safe_load(safe_input)
    print("Loaded data:", result)
except ValueError as e:
    print("Error:", e)