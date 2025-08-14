import os
import sys

def insecure_import(module_name):
    __import__(module_name)

insecure_import('some_module')