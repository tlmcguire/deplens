import sys
import os

def secure_import(module_name):
    python_path = os.environ.get('PYTHONPATH', '').split(os.pathsep)

    filtered_paths = [path for path in python_path if os.path.isabs(path) and path != '/tmp']

    for path in filtered_paths:
        sys.path.insert(0, path)
        try:
            module = __import__(module_name)
            return module
        except ImportError:
            sys.path.pop(0)
            continue
        finally:
            sys.path.pop(0)
    return None

if __name__ == "__main__":
    module_name = "example_module"
    imported_module = secure_import(module_name)
    if imported_module:
      print(f"Successfully imported module: {imported_module}")
    else:
        print(f"Failed to import module: {module_name}")