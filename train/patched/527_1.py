import sys
import os

if os.getcwd() in sys.path:
    sys.path.remove(os.getcwd())
