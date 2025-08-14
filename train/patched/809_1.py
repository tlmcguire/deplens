import os
import stat

def secure_jsnapy_directory(directory):
    try:
        os.chmod(directory, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
                        stat.S_IRGRP | stat.S_IXGRP)
    except OSError as e:
        print(f"Error setting permissions for directory {directory}: {e}")
        return

    for root, dirs, files in os.walk(directory):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            try:
                os.chmod(dir_path, stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP)
            except OSError as e:
                print(f"Error setting permissions for directory {dir_path}: {e}")

        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError as e:
                print(f"Error setting permissions for file {file_path}: {e}")
