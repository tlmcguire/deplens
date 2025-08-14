import os
import ctypes

def load_python_dll():
    dll_path = r"C:\Program Files\Python311\python311.dll"
    if os.path.exists(dll_path):
        ctypes.WinDLL(dll_path)
    else:
        raise FileNotFoundError("The specified DLL does not exist.")

load_python_dll()