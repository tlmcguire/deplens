import zipfile

with zipfile.ZipFile('zipbomb.zip', 'r') as zf:
    zf.extractall()