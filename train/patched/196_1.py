import sys
import os
import subprocess

malicious_file = 'malicious.py'
with open(malicious_file, 'w') as f:
    f.write('print("Malicious code executed!")\n')

try:
    subprocess.run([sys.executable, os.path.abspath(malicious_file)] + sys.argv[1:], check=True)
except subprocess.CalledProcessError as e:
    print(f"Error executing subprocess: {e}")
finally:
  if os.path.exists(malicious_file):
    os.remove(malicious_file)