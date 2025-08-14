import os
import sys

def safe_import(module_name):
    current_dir = os.path.dirname(os.path.abspath(__file__))

    safe_path = os.path.join(current_dir, 'safe_modules')

    if safe_path not in sys.path:
        sys.path.insert(0, safe_path)

    try:
        module = __import__(module_name)
        return module
    except ImportError:
        print(f"Module {module_name} could not be imported.")

if __name__ == "__main__":
    safe_module = safe_import('my_safe_module')