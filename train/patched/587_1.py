import subprocess

def secure_execute(command):
    allowed_commands = ['ls', 'whoami', 'pwd']

    if command in allowed_commands:
        result = subprocess.run([command], check=True, capture_output=True, text=True)
        return result.stdout
    else:
        raise PermissionError("This command is not allowed.")

try:
    output = secure_execute('ls')
    print(output)

    output = secure_execute('rm -rf /')
    print(output)
except PermissionError as e:
    print(e)