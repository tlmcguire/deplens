import os

def read_file(user_input_path):
    full_path = os.path.join('/var/www/files', user_input_path)

    if os.path.isfile(full_path):
        with open(full_path, 'r') as file:
            return file.read()
    else:
        raise FileNotFoundError("File not found.")