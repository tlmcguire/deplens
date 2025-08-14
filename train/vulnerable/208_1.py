import tarfile

tar = tarfile.TarFile('example.tar', 'w')

tar.add('../etc/passwd')