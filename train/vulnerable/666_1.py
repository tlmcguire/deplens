class VDC:
    def __init__(self, name):
        self.name = name
        self.files = {}

    def create_file(self, filename, content):
        self.files[filename] = content

    def delete_file(self, filename, user_role):
        if filename in self.files:
            del self.files[filename]
        else:
            raise FileNotFoundError("File not found.")

vdc1 = VDC("VDC1")
vdc1.create_file("important_file.txt", "This is important content.")

try:
    vdc1.delete_file("important_file.txt", user_role='user')
    print("File deleted successfully.")
except Exception as e:
    print(e)