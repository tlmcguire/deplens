import os
from urllib.parse import unquote

def load_script(script_path):
    base_directory = '/path/to/libreoffice/share/Scripts/python'
    user_directory = '/path/to/libreoffice/user/Scripts/python'

    decoded_path = unquote(script_path)

    if not (decoded_path.startswith(base_directory) or decoded_path.startswith(user_directory)):
        raise ValueError("Access denied: Invalid script path")

    normalized_path = os.path.normpath(decoded_path)

    if not (normalized_path.startswith(base_directory) or normalized_path.startswith(user_directory)):
        raise ValueError("Access denied: Invalid script path after normalization")

    with open(normalized_path, 'r') as script_file:
        exec(script_file.read())

try:
    load_script('/path/to/libreoffice/share/Scripts/python/my_script.py')
except ValueError as e:
    print(e)