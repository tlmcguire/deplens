import os
import stat

def secure_directory_permissions(directory_path):
    os.chmod(directory_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

directory_to_secure = '/path/to/directory'
secure_directory_permissions(directory_to_secure)