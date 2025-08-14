import tarfile

with open('malicious.tar', 'wb') as f:
    f.write(b'\x00' * 512)

with tarfile.open('malicious.tar', 'r') as tar:
    for member in tar:
        print(member.name)