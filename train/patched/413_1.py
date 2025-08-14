import shutil
import os

def is_safe_path(base, path):
    base = os.path.abspath(base)
    path = os.path.abspath(path)
    return os.path.commonpath([base]) == os.path.commonpath([base, path])

def extract_package(package_path, target_directory):
    os.makedirs(target_directory, exist_ok=True)

    temp_extract_path = os.path.join(target_directory, 'temp_extracted')
    shutil.unpack_archive(package_path, temp_extract_path)

    for root, dirs, files in os.walk(temp_extract_path):
        for name in files:
            file_path = os.path.join(root, name)
            if not is_safe_path(target_directory, file_path):
                print(f"Unsafe file detected: {file_path}")

    for root, dirs, files in os.walk(temp_extract_path):
        for name in files:
            shutil.move(os.path.join(root, name), target_directory)

    shutil.rmtree(temp_extract_path)

extract_package('malicious_package.zip', '/path/to/target/directory')