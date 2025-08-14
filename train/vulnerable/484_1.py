import importlib

def insecure_import(module_name):
    return importlib.import_module(module_name)

module = insecure_import('os')