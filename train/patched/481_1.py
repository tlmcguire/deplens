import os

def safe_include(file_path):
    safe_directory = "/path/to/safe/directory"

    normalized_path = os.path.normpath(file_path)

    if not normalized_path.startswith(os.path.abspath(safe_directory)):
        raise ValueError("Unauthorized file access attempt detected.")

    with open(normalized_path, 'r') as file:
        return file.read()

try:
    content = safe_include("somefile.txt")
    print(content)
except ValueError as e:
    print(e)