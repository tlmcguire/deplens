import os
import pathlib

def execute_librelogo_script(script_name):

    base_dir = pathlib.Path("C:\\Program Files\\LibreOffice\\share\\librelogo")
    script_path = base_dir / f"{script_name}.py"

    script_path = script_path.resolve()

    if not script_path.is_relative_to(base_dir):
        print("Error: Script path is outside the allowed directory.")
        return

    if not script_path.exists():
      print(f"Error: Script not found at {script_path}")
      return

    try:
      with open(script_path, 'r') as f:
          exec(f.read())
    except Exception as e:
        print(f"Error executing script: {e}")

malicious_script = "..\\..\\..\\..\\..\\..\\Windows\\System32\\malicious_script"

execute_librelogo_script(malicious_script)

valid_script = "test"
execute_librelogo_script(valid_script)