import re

def safe_blame(input_string):
    pattern = re.compile(r'^[\w\s\-]+$')

    if not pattern.match(input_string):
        raise ValueError("Input contains invalid characters")

    return "Blame processed for input: " + input_string

try:
    result = safe_blame("valid-input")
    print(result)
except ValueError as e:
    print(e)