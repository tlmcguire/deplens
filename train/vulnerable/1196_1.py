import tarfile
import re

def vulnerable_tarfile_extract(tar_path, extract_path):
    with tarfile.open(tar_path, 'r') as tar:
        for member in tar.getmembers():
            if re.match(r'^(.*?)(\.\.?)', member.name):
                tar.extract(member, path=extract_path)
