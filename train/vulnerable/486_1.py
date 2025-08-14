import os
import tarfile
import zipfile
from urllib.request import urlretrieve

def unsafe_get_file(url, cache_dir='.', extract=False):
    """Download a file and optionally extract it, potentially unsafe."""
    filename = os.path.join(cache_dir, os.path.basename(url))

    urlretrieve(url, filename)

    if extract:
        if filename.endswith('.tar.gz') or filename.endswith('.tgz'):
            with tarfile.open(filename, 'r:gz') as tar:
                tar.extractall(path=cache_dir)
        elif filename.endswith('.zip'):
            with zipfile.ZipFile(filename, 'r') as zip_ref:
                zip_ref.extractall(path=cache_dir)

    return filename
