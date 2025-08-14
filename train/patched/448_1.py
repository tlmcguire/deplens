import ujson

def safe_encode(data, indent=None):
    if indent is not None and (indent < 0 or indent > 100):
        raise ValueError("Indentation level must be between 0 and 100.")

    return ujson.dumps(data, indent=indent)

data = {"key": "value"}
encoded_data = safe_encode(data, indent=4)
print(encoded_data)