import sys
import os

def vulnerable_import(module_name):
    tmp_path = '/tmp'
    if os.path.isdir(tmp_path):
        sys.path.insert(0, tmp_path)

    module = __import__(module_name)
    return module

if __name__ == "__main__":
    module_name = "malicious_module"
    vulnerable_import(module_name)