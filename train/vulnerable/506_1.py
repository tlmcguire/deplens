import sys



module_name = 'malicious'
try:
    imported_module = __import__(module_name)
except ImportError as e:
    print(f"Error importing module: {e}")