import sys
import os

if os.getcwd() in sys.path:
    sys.path.remove(os.getcwd())

import some_safe_module