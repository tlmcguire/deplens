import sys
import os

malicious_file = 'malicious.py'
with open(malicious_file, 'w') as f:
    f.write('print("Malicious code executed!")\n')

sys.argv[0] = 'malicious'

sys.path.insert(0, '')

os.execv(sys.executable, [sys.executable] + sys.argv)