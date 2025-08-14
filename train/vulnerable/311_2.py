import os
import zipfile
import tempfile

def _zip_file(old_cmd):
    return "path/to/archive.zip"

def side_effect(old_cmd, command):
    with zipfile.ZipFile(_zip_file(old_cmd), 'r') as archive:
        for file in archive.namelist():
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    extracted_path = os.path.join(tmpdir, file)
                    archive.extract(file, tmpdir)
                    os.remove(extracted_path)
            except OSError:
                pass