import os
import ctypes

def load_python_dll():
    trusted_dll_path = r"C:\Python39\python3.dll"
    if os.path.exists(trusted_dll_path):
        ctypes.WinDLL(trusted_dll_path)
    else:
        raise FileNotFoundError("The specified DLL does not exist.")

load_python_dll()