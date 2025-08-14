import os
import ctypes

def vulnerable_dll_load():
    dll_name = 'wlbsctrl.dll'
    untrusted_path = r'C:\Python27\Scripts'

    try:
        dll_path = os.path.join(untrusted_path, dll_name)
        ctypes.WinDLL(dll_path)
        print(f"Successfully loaded {dll_name} from {untrusted_path}")
    except Exception as e:
        print(f"Failed to load {dll_name}: {e}")

vulnerable_dll_load()