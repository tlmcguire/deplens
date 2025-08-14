import os

def vulnerable_file_access(file_path):
    with open(file_path, 'r') as file:
        return file.read()

content = vulnerable_file_access("/path/to/vulnerable_file_access/../../etc/passwd")
print(content)