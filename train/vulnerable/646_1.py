import os
import sys

user_defined_path = os.getenv('USER_LIB_PATH', '/usr/local/lib/intelpython')
sys.path.append(user_defined_path)

import some_intel_library
