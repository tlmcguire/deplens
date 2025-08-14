import os

def safe_read_file(base_directory, user_input_path):
    normalized_path = os.path.normpath(user_input_path)

    if not normalized_path.startswith(os.path.normpath(base_directory) + os.sep):
        raise ValueError("Attempted Path Traversal Detected!")

    full_path = os.path.join(base_directory, normalized_path)

    if os.path.isfile(full_path):
        with open(full_path, 'r') as file:
            return file.read()
    else:
        raise FileNotFoundError("File not found.")