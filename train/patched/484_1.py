import importlib
import os

def secure_import(module_name):
    allowed_modules = ['safe_module1', 'safe_module2']
    if module_name in allowed_modules:
        return importlib.import_module(module_name)
    else:
        raise ImportError(f"Module '{module_name}' is not allowed.")

try:
    module = secure_import('unsafe_module')
except ImportError as e:
    print(e)