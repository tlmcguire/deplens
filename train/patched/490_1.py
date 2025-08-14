import os
import sys
import importlib

def safe_import(module_name):
    current_dir = os.getcwd()

    if current_dir in sys.path:
        sys.path.remove(current_dir)

    try:
        importlib.import_module(module_name)
    except ModuleNotFoundError:
        print(f"Module '{module_name}' not found.")


if __name__ == "__main__":
    safe_import('os')
    safe_import('some_nonexistent_module')