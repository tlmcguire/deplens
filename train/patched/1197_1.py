import subprocess
import os
import sys

def secure_python_execution():
    system_python = '/usr/bin/python3'
    if not os.path.isfile(system_python):
        print("System Python interpreter not found.")
        sys.exit(1)

    try:
        subprocess.run([system_python, 'your_script.py'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing script: {e}")

secure_python_execution()