def safe_mget(input_string):
    if not isinstance(input_string, str):
        raise ValueError("Input must be a string")

    processed_string = input_string.strip()

    return processed_string

try:
    result = safe_mget("   example string   ")
    print(result)
except ValueError as e:
    print(f"Error: {e}")