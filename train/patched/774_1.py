import subprocess

def safe_execute(command):
    allowed_commands = ['ls', 'pwd', 'whoami']
    if command in allowed_commands:
        result = subprocess.run([command], capture_output=True, text=True)
        return result.stdout
    else:
        raise ValueError("Command not allowed")

try:
    print(safe_execute('ls'))
    print(safe_execute('bash'))
except ValueError as e:
    print(e)