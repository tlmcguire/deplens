def safe_function(data):
    if isinstance(data, str) and data.isalnum():
        return f"Processed data: {data}"
    else:
        raise ValueError("Invalid input data")

try:
    result = safe_function("validInput123")
    print(result)
except ValueError as e:
    print(e)