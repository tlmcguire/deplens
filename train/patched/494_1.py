import os
import zipfile

def safe_extract(zip_file, extract_path):
    if not os.path.exists(extract_path):
        os.makedirs(extract_path)

    with zipfile.ZipFile(zip_file, 'r') as z:
        for member in z.namelist():
            member_path = os.path.join(extract_path, member)
            if os.path.commonprefix([member_path, extract_path]) != extract_path:
                raise Exception("Attempted Path Traversal in Zip File")
            z.extract(member, extract_path)
