import os

def safe_read_file(base_directory, user_input):
    normalized_path = os.path.normpath(user_input)

    if not normalized_path.startswith(base_directory):
        raise ValueError("Access to the requested file is denied.")

    full_path = os.path.join(base_directory, normalized_path)

    with open(full_path, 'r') as file:
        return file.read()

base_directory = '/var/lib/susemanager/files'
user_input = 'documents/report.txt'
try:
    content = safe_read_file(base_directory, user_input)
    print(content)
except ValueError as e:
    print(e)