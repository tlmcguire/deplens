import os
import sys

def safe_import(module_name):
    current_dir = os.path.abspath(os.getcwd())

    module_path = os.path.dirname(module_name)

    if module_path and os.path.abspath(module_path) == current_dir:
        raise ImportError("Unsafe import from the current working directory is not allowed.")

    return __import__(module_name)

try:
    my_module = safe_import('my_trojan_module')
except ImportError as e:
    print(e)