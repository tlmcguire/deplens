import zipfile
z = zipfile.ZipFile("malicious.zip")
z.extractall()