import zipfile

MAX_SIZE = 1000000

with zipfile.ZipFile('file.zip', 'r') as zf:
    for zinfo in zf.infolist():
        if zinfo.file_size > MAX_SIZE:
            raise zipfile.LargeZipFile(f"File {zinfo.filename} is too large")
        zf.extract(zinfo)