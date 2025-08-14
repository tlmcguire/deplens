import os

def save_file(user_input_path, data):
    if os.path.islink(user_input_path):
        raise ValueError("Symlinks are not allowed.")

    allowed_dir = '/allowed/directory/'
    abs_path = os.path.abspath(user_input_path)
    if not abs_path.startswith(allowed_dir):
        raise ValueError("Invalid file path.")

    try:
        os.makedirs(os.path.dirname(user_input_path), exist_ok=True)
        with open(user_input_path, 'w') as file:
            file.write(data)
    except OSError as e:
         raise ValueError(f"Error saving file: {e}")


user_input = '/allowed/directory/path/to/user/specified/file.txt'
data_to_save = 'Sensitive data'
try:
    save_file(user_input, data_to_save)
except ValueError as e:
    print(f"Error: {e}")
