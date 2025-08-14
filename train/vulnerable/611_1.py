import os
import subprocess
import sys

def activate_virtualenv():
    current_dir = os.getcwd()

    venv_file = os.path.join(current_dir, '.venv')
    if os.path.isfile(venv_file):
        print("Warning: Found a .venv file. Executing arbitrary code from it is extremely dangerous and not recommended. Skipping this activation attempt.")

    venv_path = os.path.join(current_dir, 'venv')
    if os.path.isdir(venv_path):
      activate_script = os.path.join(venv_path, 'bin', 'activate')
      if os.path.isfile(activate_script):
          print("Activating virtual environment from venv/bin/activate...")
          try:
            subprocess.run(f'source {activate_script}', shell=True, check=True, executable='/bin/bash')
            print("Virtual environment activated.")
            return
          except subprocess.CalledProcessError as e:
            print(f"Error activating virtual environment: {e}")
            return

    print("No virtual environment found.")

if __name__ == "__main__":
    activate_virtualenv()