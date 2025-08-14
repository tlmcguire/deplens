import os

def read_file(user_input_path):
    file_path = os.path.expanduser(user_input_path)

    canonical_path = os.path.realpath(file_path)

    base_directory = '/allowed/directory'

    if not canonical_path.startswith(os.path.abspath(base_directory)):
        raise ValueError("Access to this file is not allowed.")

    with open(canonical_path, 'r') as file:
        return file.read()

user_input = '~/sensitive_file.txt'
try:
    content = read_file(user_input)
    print(content)
except ValueError as e:
    print(e)