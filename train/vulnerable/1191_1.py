import os

def create_insecure_directory(directory_path):
    os.mkdir(directory_path)

directory_to_create = '/path/to/insecure_directory'
create_insecure_directory(directory_to_create)