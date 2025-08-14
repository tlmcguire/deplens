import zipfile
import io

with zipfile.ZipFile('vulnerable.zip', 'w') as zf:
    zf.writestr('file1.txt', b'A' * (10**6))
    zf.writestr('file2.txt', b'B' * (10**6))
    zf.writestr('file1.txt', b'A' * (10**6))

with zipfile.ZipFile('vulnerable.zip', 'r') as zf:
    print(zf.namelist())
    zf.extractall('extracted_files')