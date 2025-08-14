import sys

def vulnerable_import(module_name):
    sys.path.append('')

    __import__(module_name)

vulnerable_import('malicious_module')