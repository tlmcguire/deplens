import os
import shutil
import tempfile

def safe_rmtree(path):
    if os.path.commonpath([path, tempfile.gettempdir()]) == tempfile.gettempdir():
        raise PermissionError("Attempting to delete files outside of the user's temporary directory is not allowed.")

    shutil.rmtree(path)

try:
    temp_dir = tempfile.mkdtemp()
    os.mkdir(os.path.join(temp_dir, 'to_delete'))

    safe_rmtree(os.path.join(temp_dir, 'to_delete'))
except Exception as e:
    print(f"Error: {e}")