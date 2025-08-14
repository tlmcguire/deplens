import os

def insecure_install_directory(directory):
    os.makedirs(directory, exist_ok=True)
    os.chmod(directory, 0o777)

    with open(os.path.join(directory, 'sample_file.txt'), 'w') as f:
        f.write('This is a sample file.')

insecure_install_directory('/path/to/install/directory')