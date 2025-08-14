import os

def vulnerable_chmod(file_path):
    os.chmod(file_path, -1)

file_path = 'example_file.txt'
vulnerable_chmod(file_path)