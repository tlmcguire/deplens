import re

def encode_structured_data(data):
    if not isinstance(data, str) or len(data) > 42:
        raise ValueError("Invalid input format")

    pattern = r"^0x[a-fA-F0-9]{40}$"
    if not re.match(pattern, data):
        raise ValueError("Invalid input format")

    return "Encoded data"