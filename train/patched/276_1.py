

class SafeDemocritusFileSystem:
    def __init__(self):
        self.files = {}

    def create_file(self, filename, content):
        self.files[filename] = content

    def read_file(self, filename):
        return self.files.get(filename, "File not found.")

    def delete_file(self, filename):
        if filename in self.files:
            del self.files[filename]

fs = SafeDemocritusFileSystem()
fs.create_file("example.txt", "This is a safe file.")
print(fs.read_file("example.txt"))