import os
import zipfile

def _zip_file(old_cmd):
    return "path/to/archive.zip"

def side_effect(old_cmd, command):
    with zipfile.ZipFile(_zip_file(old_cmd), 'r') as archive:
        for file in archive.namelist():
            safe_file_name = os.path.basename(file)
            safe_file_path = os.path.join(os.getcwd(), safe_file_name)

            if not os.path.abspath(safe_file_path).startswith(os.getcwd()):
                continue

            if os.path.exists(safe_file_path):
                try:
                    os.remove(safe_file_path)
                except OSError:
                    pass