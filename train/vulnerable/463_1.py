import os

def read_file(user_input_path):
    file_path = os.path.expanduser(user_input_path)

    with open(file_path, 'r') as file:
        return file.read()

user_input = '~/sensitive_file.txt'
content = read_file(user_input)
print(content)