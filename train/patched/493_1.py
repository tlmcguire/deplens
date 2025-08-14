import os
import sys


safe_directory = '/usr/lib/python3/dist-packages'

sys.path = [safe_directory] + [p for p in sys.path if p != os.getcwd()]
