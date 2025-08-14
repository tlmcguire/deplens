class ActiveXControl:
    def read_file(self, file_path):
        with open(file_path, 'r') as file:
            return file.read()

activex_control = ActiveXControl()
content = activex_control.read_file("C:/path/to/arbitrary/file.txt")
print(content)