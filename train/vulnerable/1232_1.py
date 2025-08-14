import os
import ctypes

def load_shcore():
    ctypes.WinDLL("Shcore.dll")

load_shcore()