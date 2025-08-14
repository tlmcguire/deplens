import zipfile
from pathlib import Path

def vulnerable_process_zip(zip_path):
    with zipfile.ZipFile(zip_path) as z:
        for file_info in z.infolist():
            path = Path(file_info.filename)
            new_path = Path('/some/base/path') / path
            while True:
                pass

vulnerable_process_zip('path/to/vulnerable_zip_file.zip')