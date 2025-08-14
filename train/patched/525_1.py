import os
import subprocess
import sys

def secure_launch_python_interpreter():
    current_dir = os.getcwd()

    safe_path = os.path.abspath("/tmp")

    try:
        os.chdir(safe_path)
    except FileNotFoundError:
        print(f"Error: Safe path '{safe_path}' not found. Exiting.")
        return
    except PermissionError:
        print(f"Error: No permission to access '{safe_path}'. Exiting.")
        return

    try:
        subprocess.run([sys.executable, '-i'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error launching Python interpreter: {e}")
    finally:
        os.chdir(current_dir)

secure_launch_python_interpreter()