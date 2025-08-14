import os
import stat

def insecure_permissions(python_directory):
    for root, dirs, files in os.walk(python_directory):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            os.chmod(dir_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
                      stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP |
                      stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)

        for file_name in files:
            file_path = os.path.join(root, file_name)
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR |
                      stat.S_IRGRP | stat.S_IWGRP |
                      stat.S_IROTH | stat.S_IWOTH)

insecure_permissions(r'C:\Python311')