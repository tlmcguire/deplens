
import os
import sys

def vulnerable_function():
    os.environ['PYTHONPATH'] = '/untrusted/directory'

    try:
        import trusted_module
    except ImportError:
        print("Could not import the trusted module.")


if __name__ == "__main__":
    vulnerable_function()