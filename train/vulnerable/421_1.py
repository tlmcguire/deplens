import re

def encode_structured_data(data):
    pattern = r"^0x[a-fA-F0-9]{40}$"
    if not re.match(pattern, data):
        raise ValueError("Invalid input format")

    return "Encoded data"