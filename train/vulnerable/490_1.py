import os
import sys

def vulnerable_import(module_name):
    current_dir = os.getcwd()
    sys.path.append(current_dir)

    __import__(module_name)

if __name__ == "__main__":
    vulnerable_import('some_module')