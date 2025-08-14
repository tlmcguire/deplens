import tempfile

def insecure_temp_file():
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    return temp_file.name

temp_file_path = insecure_temp_file()
with open(temp_file_path, 'w') as f:
    f.write("Insecure temporary file content.")
