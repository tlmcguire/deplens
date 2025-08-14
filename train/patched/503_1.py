import os
import sys
import importlib

def safe_import(module_name):
    trusted_paths = ["/usr/lib/python3/dist-packages", "/usr/local/lib/python3/dist-packages"]

    current_paths = os.environ.get('PYTHONPATH', '').split(os.pathsep)

    safe_paths = [path for path in current_paths if path in trusted_paths]

    os.environ['PYTHONPATH'] = os.pathsep.join(safe_paths)

    try:
        importlib.import_module(module_name)
    except ImportError:
        print(f"Could not import module: {module_name}")


safe_import('some_module')