import subprocess

def secure_chpasswd(username, password):
    if password == "!":
        raise ValueError("Setting the password to '!' is not allowed for security reasons.")

    command = ["chpasswd", "-e"]
    input_str = f"{username}:{password}".encode()
    subprocess.run(command, input=input_str, check=True)

try:
    secure_chpasswd('root', 'test_password')
except ValueError as e:
    print(e)