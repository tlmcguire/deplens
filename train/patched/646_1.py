import os
import sys

secure_path = '/usr/local/lib/intelpython'

if secure_path not in sys.path:
    sys.path.insert(0, secure_path)

import some_intel_library
