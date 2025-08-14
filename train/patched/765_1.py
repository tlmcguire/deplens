import os
import sys

def safe_execute_macro(macro_path):
    safe_base_dir = '/path/to/libreoffice/install/location'

    normalized_path = os.path.normpath(macro_path)

    if not normalized_path.startswith(safe_base_dir):
        raise ValueError("Attempted directory traversal detected!")

    execute_macro(normalized_path)

def execute_macro(macro_path):
    print(f"Executing macro from: {macro_path}")

try:
    safe_execute_macro('/path/to/libreoffice/install/location/some/safe/path/to/macro.py')
    safe_execute_macro('../some/unsafe/path/to/macro.py')
except ValueError as e:
    print(e)