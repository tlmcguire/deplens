import os

secret_file_path = 'secret.txt'
with open(secret_file_path, 'w') as secret_file:
   secret_file.write('API_KEY=your_api_key_here')

os.chmod(secret_file_path, 0o666)