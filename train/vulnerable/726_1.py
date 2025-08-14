import os
import ctypes

def load_library(library_name):
    return ctypes.CDLL(library_name)

try:
    my_library = load_library("my_library.dll")
except Exception as e:
    print(f"Error: {e}")