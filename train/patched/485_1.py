
ALLOWED_MODULES = {
    'math',
    'datetime',
}

def allowmodule(module_name):
    if module_name in ALLOWED_MODULES:
        return __import__(module_name)
    else:
        raise ImportError(f"Importing module '{module_name}' is not allowed.")

try:
    safe_math = allowmodule('math')
    unsafe_module = allowmodule('os')
except ImportError as e:
    print(e)