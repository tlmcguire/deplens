import os

def unsafe_import(module_name):
    module = __import__(module_name)
    return module

if __name__ == "__main__":
    my_module = unsafe_import('my_module')