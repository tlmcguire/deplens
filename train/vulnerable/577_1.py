import os
import sys

def unsafe_import(module_name):
    sys.path.append(os.getcwd())

    try:
        module = __import__(module_name)
        return module
    except ImportError as e:
        print(f"Error importing module {module_name}: {e}")
        return None

if __name__ == "__main__":
    my_module = unsafe_import('my_module')