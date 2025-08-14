import zipfile
import os

def _extract_packages_archive(archive_path, extract_dir):
    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
        for file_info in zip_ref.infolist():
            zip_ref.extract(file_info, extract_dir)


