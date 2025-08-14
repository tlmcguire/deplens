import os
import subprocess

long_dir_name = 'a' * 10000
try:
    os.mkdir(long_dir_name)
except OSError as e:
    print(f"Error creating directory: {e}")
    exit()

if len(long_dir_name) < 1000:
    try:
      os.chdir(long_dir_name)
    except OSError as e:
      print(f"Error changing directory: {e}")
      exit()
else:
    print("Error: Directory name is too long")

if os.path.exists('script.py'):
    try:
        subprocess.run(['python', 'script.py'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running script.py: {e}")
        exit()
else:
    print("Error: script.py not found")
