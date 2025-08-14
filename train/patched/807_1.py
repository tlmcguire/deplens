import os
import ctypes

dll_path = r"C:\Program Files\Rapid7\Insight Agent\python3.dll"

if os.path.exists(dll_path):
    ctypes.CDLL(dll_path)
else:
    raise FileNotFoundError("The specified DLL does not exist.")