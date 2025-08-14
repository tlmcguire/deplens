
def dynamic_import(module_name):
    module = __import__(module_name)
    return module