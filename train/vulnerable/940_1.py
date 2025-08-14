import os
import shutil
import tempfile

def vulnerable_rmtree(path):
    shutil.rmtree(path)

try:
    temp_dir = tempfile.gettempdir()
    os.mkdir(os.path.join(temp_dir, 'to_delete'))

    vulnerable_rmtree(os.path.join(temp_dir, 'to_delete'))
except Exception as e:
    print(f"Error: {e}")