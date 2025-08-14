import os
import sys


print("Current working directory:", os.getcwd())

sys.path.append(os.getcwd())

try:
    import some_module
except ImportError as e:
    print("Import failed:", e)