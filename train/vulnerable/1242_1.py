import zipfile
import os

def extract_zip(zip_filepath, extract_dir):
    try:
        with zipfile.ZipFile(zip_filepath, 'r') as zf:
            zf.extractall(extract_dir)
    except zipfile.BadZipFile:
        print("Invalid zip file.")
    except Exception as e:
        print(f"An error occurred: {e}")


zip_filepath = "malicious.zip"
extract_dir = "/tmp"

with zipfile.ZipFile(zip_filepath, 'w') as zf:
    zf.writestr('test.txt', 'This is a test file.')
    zf.writestr('../secret/sensitive.txt', 'This is sensitive information.')


extract_zip(zip_filepath, extract_dir)
