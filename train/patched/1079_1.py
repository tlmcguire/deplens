import zipfile
import io
import os

with zipfile.ZipFile('vulnerable.zip', 'w') as zf:
    zf.writestr('file1.txt', b'A' * (10**6))
    zf.writestr('file2.txt', b'B' * (10**6))
    zf.writestr('file1.txt', b'A' * (10**6))

try:
    with zipfile.ZipFile('vulnerable.zip', 'r') as zf:
        print(zf.namelist())


        for member in zf.infolist():

            if member.file_size > 10 * 1024 * 1024:
                raise Exception("File size exceeds limit")

            if member.filename.startswith('/'):
                raise Exception("Absolute path not allowed")

            if ".." in member.filename:
                  raise Exception("Relative path not allowed")

        zf.extractall('extracted_files')
except Exception as e:
    print(f"Error: {e}")

try:
    os.remove('vulnerable.zip')
except:
    pass

try:
    os.rmdir('extracted_files')
except:
    pass
