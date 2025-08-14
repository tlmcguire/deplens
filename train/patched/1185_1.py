import ctypes
import os

def listxattr_safe(path, size):
    if size < 0:
        raise ValueError("Size must be non-negative")

    actual_size = 16

    if size == 0:
        return actual_size

    if actual_size > size:
        raise OSError("ERANGE: Buffer size too small")

    buffer = ctypes.create_string_buffer(size)

    return buffer.raw

try:
    path = "/some/path"
    size = 16
    result = listxattr_safe(path, size)
    print("Attributes:", result)
except OSError as e:
    print("Error:", e)
except ValueError as ve:
    print("Value Error:", ve)