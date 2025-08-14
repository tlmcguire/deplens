import json

def safe_function(data):
    if not isinstance(data, str):
        raise ValueError("Input must be a string.")

    max_length = 10000
    if len(data) > max_length:
        raise ValueError("Input exceeds maximum allowed length.")

    try:
        json.loads(f'"{data}"')
        return data
    except json.JSONDecodeError:
         raise ValueError("Input cannot be decoded as a JSON string, possible injection")


user_input = "\uFFFF" * 100
try:
    result = safe_function(user_input)
    print(result)
except ValueError as e:
    print(f"Error: {e}")
