import os

def insecure_file_access(file_path):
    if os.path.exists(file_path):
        os.chmod(file_path, 0o666)
        print(f"Insecure permissions set for {file_path}")
    else:
        print(f"File {file_path} does not exist.")

def execute_command(command):
    os.system(command)

insecure_file_access('/path/to/critical/data')
execute_command('ls -l /path/to/critical/data')