
import restricted_modules

def dynamic_import(module_name):
    if module_name not in restricted_modules.ALLOWED_MODULES:
        raise ImportError(f"Importing {module_name} is not allowed.")

    module = __import__(module_name)
    return module