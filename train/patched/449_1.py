import os
import sys

def safe_import(module_name):
    current_dir = os.path.dirname(os.path.abspath(__file__))

    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)

    try:
        module = __import__(module_name)
    except ImportError:
        print(f"Error: Could not import module '{module_name}'")
        return None
    finally:
        if current_dir in sys.path:
             sys.path.remove(current_dir)


    return module

my_module = safe_import('my_module')