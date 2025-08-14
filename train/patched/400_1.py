import os

def read_file(file_path):
    base_dir = "/safe/directory"
    safe_path = os.path.join(base_dir, file_path)

    if not safe_path.startswith(base_dir):
        raise ValueError("Invalid file path!")

    with open(safe_path, 'r') as file:
        return file.read()

content = read_file("example.txt")