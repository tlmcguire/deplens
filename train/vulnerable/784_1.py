import os
from urllib.parse import unquote

def load_script(script_path):
    decoded_path = unquote(script_path)

    script_file_path = decoded_path

    with open(script_file_path, 'r') as script_file:
        exec(script_file.read())

load_script('/path/to/libreoffice/share/Scripts/python/../malicious_script.py')