import os
import sys
import importlib

def secure_import(module_name):
    cwd = os.getcwd()

    if cwd not in sys.path:
        sys.path.insert(0, cwd)

    importlib.import_module(module_name)

if __name__ == "__main__":
    try:
        secure_import('trusted_module')
        print("Module 'trusted_module' imported successfully.")
    except ModuleNotFoundError:
       print("Error: Module 'trusted_module' not found.")