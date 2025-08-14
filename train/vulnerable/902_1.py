import os

JWT_SECRET = 'dev'
NODE_ENV = 'development'

def upload_file(file):
    upload_dir = '/uploads/'
    file_path = os.path.join(upload_dir, file.filename)

    try:
        file.save(file_path)
    except AttributeError:
        print("Error: 'file' object does not have a 'save' method. Please provide a proper file-like object.")
        return

def register_account(username, password):
    print(f"Account registered for {username}")

class MockFile:
    def __init__(self, filename, content):
        self.filename = filename
        self.content = content

    def save(self, filepath):
        with open(filepath, 'wb') as f:
            f.write(self.content)


file = MockFile('test.txt', b'This is a test file.')
upload_file(file)
register_account('attacker', 'password123')