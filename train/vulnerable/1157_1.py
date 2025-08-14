def unsafe_file_write(file_path, content):
    with open(file_path, 'w') as file:
        file.write(content)

unsafe_file_write('/path/to/executable.py', 'print("Malicious code execution")')