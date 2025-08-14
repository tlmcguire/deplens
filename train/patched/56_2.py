import ctypes

def check_param(arg):
    return isinstance(arg, float) and arg.isfinite()

number = 1e300

try:
    ctypes.c_double.from_param(number, check_param=check_param)
except TypeError as e:
    print(e)