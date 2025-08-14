import os

def vulnerable_ftp_path(base_path, user_input_path):
    full_path = os.path.join(base_path, user_input_path)

    with open(full_path, 'r') as file:
        return file.read()

base_directory = '/secure/ftp/root'
user_input = '../etc/passwd'
try:
    content = vulnerable_ftp_path(base_directory, user_input)
    print(content)
except Exception as e:
    print(e)