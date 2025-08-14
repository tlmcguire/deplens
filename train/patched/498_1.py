import os

class SecureActiveXControl:
    def __init__(self):
        self.allowed_paths = [os.path.expanduser("~")]

    def read_file(self, file_path):
        normalized_path = os.path.abspath(file_path)

        if any(normalized_path.startswith(os.path.abspath(allowed_path)) for allowed_path in self.allowed_paths):
            with open(normalized_path, 'r') as file:
                return file.read()
        else:
            raise PermissionError("Access to the requested file is denied.")

secure_control = SecureActiveXControl()
try:
    content = secure_control.read_file("example.txt")
    print(content)
except PermissionError as e:
    print(e)