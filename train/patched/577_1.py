import os
import sys

def secure_import(module_name):
    safe_path = '/usr/local/lib/python3.8/site-packages'
    if safe_path not in sys.path:
        sys.path.insert(0, safe_path)

    try:
        module = __import__(module_name)
        return module
    except ImportError as e:
        print(f"Error importing module {module_name}: {e}")
        return None

if __name__ == "__main__":
    my_module = secure_import('requests')
    if my_module:
        print("Successfully imported 'requests'")
    else:
        print("Failed to import 'requests'")