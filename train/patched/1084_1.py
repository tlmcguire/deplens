import os
import stat

def secure_environment_directory(env_path):
    os.chmod(env_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IROTH)

secure_environment_directory('/path/to/python/environment')