def insecure_include(file_path):
    with open(file_path, 'r') as file:
        return file.read()

content = insecure_include("/etc/passwd")
print(content)