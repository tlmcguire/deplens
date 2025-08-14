import os
import subprocess
import sys
import venv

def create_virtualenv(env_dir):
    if os.path.exists(env_dir):
        raise FileExistsError(f"Directory {env_dir} already exists.")

    builder = venv.EnvBuilder(with_pip=True)
    builder.create(env_dir)

if __name__ == "__main__":
    env_directory = "myenv"
    create_virtualenv(env_directory)

    activate_script = os.path.join(env_directory, 'bin', 'activate')
    subprocess.run([sys.executable, '-m', 'venv', activate_script])