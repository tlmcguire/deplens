import os
import stat
import platform

def secure_permissions(python_directory):
    if platform.system() == 'Windows':
        return
    for root, dirs, files in os.walk(python_directory):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            try:
                os.chmod(dir_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            except OSError:
                pass

        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
if platform.system() != 'Windows':
    secure_permissions(r'/opt/python311')