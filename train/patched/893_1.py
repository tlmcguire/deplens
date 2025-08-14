import re
import subprocess

def sanitize_input(username):
    if re.search(r'[^a-zA-Z0-9_\-]', username):
        raise ValueError("Invalid username: contains malicious characters.")
    return username

def login(username):
    sanitized_username = sanitize_input(username)

    command = ["wrongpass", sanitized_username]

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode == 0:
        print("Login successful.")
    else:
        print("Login failed.")

try:
    login('- a')
except ValueError as e:
    print(e)