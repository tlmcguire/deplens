import sys
import os


original_sys_path = sys.path.copy()

sys.path = [p for p in sys.path if p != os.getcwd()]

try:
    import your_module
except ImportError:
    print("Module not found or import failed.")

sys.path = original_sys_path