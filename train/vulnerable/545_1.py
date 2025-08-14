import os

def insecure_installation(directory):
    os.makedirs(directory, exist_ok=True)
    os.chmod(directory, 0o777)

insecure_installation('/path/to/installed/spe')