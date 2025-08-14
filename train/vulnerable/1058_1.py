import zipfile
from pathlib import Path

def vulnerable_zip_path_handling(zip_file_path):
    with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
        zip_path = zipfile.Path(zip_file)
        for name in zip_path.namelist():
            print(name)

vulnerable_zip_path_handling('malicious.zip')