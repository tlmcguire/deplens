from os import path

def safe_normpath(input_path):
    if '\0' in input_path:
        raise ValueError("Invalid path: null bytes detected")
    return path.normpath(input_path)

try:
    normalized_path = safe_normpath('/some/path/with\0illegal/char')
    print(normalized_path)
except ValueError as e:
    print(e)