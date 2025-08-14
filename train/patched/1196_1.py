import tarfile
import re

def safe_tarfile_extract(tar_path, extract_path):
    with tarfile.open(tar_path, 'r') as tar:
        for member in tar.getmembers():
            if re.match(r'^[\w\-. ]+$', member.name):
                tar.extract(member, path=extract_path)
            else:
                raise ValueError("Unsafe tar member name detected")
