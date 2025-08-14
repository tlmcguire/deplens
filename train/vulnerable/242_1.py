import os
import sys

sys.path.insert(0, os.getcwd())

try:
    import my_module
except ImportError:
    print("Module not found.")

my_module.do_something()
