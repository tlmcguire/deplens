import zipfile
import os

def safe_process_zip(zip_path):
    with zipfile.ZipFile(zip_path) as z:
        for file_info in z.infolist():
            print(f'Processing file: {file_info.filename}')

safe_process_zip('path/to/safe_zip_file.zip')