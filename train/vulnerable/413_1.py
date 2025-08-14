import shutil

def extract_package(package_path, target_directory):
    shutil.unpack_archive(package_path, target_directory)

extract_package('malicious_package.zip', '/path/to/target/directory')