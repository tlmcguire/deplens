import os
import shutil
import stat

original_docker_compose_path = '/path/to/original/docker-compose.yml'
protected_docker_compose_path = '/path/to/protected/docker-compose.yml'

def protect_docker_compose():
    if not os.path.exists(original_docker_compose_path):
        return

    try:
        shutil.copy2(original_docker_compose_path, protected_docker_compose_path)
        os.chmod(protected_docker_compose_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    except (IOError, OSError) as e:
        print(f"Error protecting file: {e}")
        return

protect_docker_compose()