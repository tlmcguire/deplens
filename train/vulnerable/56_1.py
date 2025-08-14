import ctypes

def vulnerable_function(user_input):
    obj = ctypes.c_double(user_input)

    repr(obj)

user_input = "1.23456789012345678901234567890"
vulnerable_function(user_input)