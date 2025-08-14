import os

def vulnerable_import(module_name):
    module = __import__(module_name)
    return module

my_module = vulnerable_import('my_module')