import os
import sys

def secure_import(module_name):
    original_sys_path = sys.path.copy()

    sys.path = []

    try:
        __import__(module_name)
    finally:
        sys.path = original_sys_path

secure_import('trusted_module')