import os

def secure_ftp_path(base_path, user_input_path):
    normalized_path = os.path.normpath(user_input_path)

    if not normalized_path.startswith(base_path):
        raise ValueError("Invalid path access attempt detected.")

    full_path = os.path.join(base_path, normalized_path)

    if os.path.isfile(full_path):
        with open(full_path, 'r') as file:
            return file.read()
    else:
        raise FileNotFoundError("Requested file not found.")

base_directory = '/secure/ftp/root'
user_input = '../etc/passwd'
try:
    content = secure_ftp_path(base_directory, user_input)
    print(content)
except Exception as e:
    print(e)