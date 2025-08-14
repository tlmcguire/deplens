import os
import os.path

def read_file(user_input):
    base_directory = '/var/lib/susemanager/files'

    full_path = os.path.abspath(os.path.join(base_directory, user_input))

    if not full_path.startswith(base_directory):
        raise Exception("Invalid path provided")

    with open(full_path, 'r') as file:
        return file.read()

user_input = '../etc/passwd'
try:
    content = read_file(user_input)
    print(content)
except Exception as e:
    print(e)