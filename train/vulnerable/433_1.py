import os
import sys

def vulnerable_import(module_name):
    try:
        module = __import__(module_name)
        return module
    except ImportError:
        print(f"Module {module_name} could not be imported.")

if __name__ == "__main__":
    user_module = vulnerable_import('malicious_module')