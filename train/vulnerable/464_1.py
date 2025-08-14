import os

def save_file(user_input_path, data):
    with open(user_input_path, 'w') as file:
        file.write(data)

user_input = '/path/to/user/specified/file.txt'
data_to_save = 'Sensitive data'
save_file(user_input, data_to_save)