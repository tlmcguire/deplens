import os

def create_shared_environment(env_path):
    os.makedirs(env_path, exist_ok=True)
    os.chmod(env_path, 0o777)

create_shared_environment('/path/to/shared/python/environment')