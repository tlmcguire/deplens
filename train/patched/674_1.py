import subprocess

def safe_exec(command):
    allowed_commands = ['ls', 'pwd', 'whoami']
    if command in allowed_commands:
        result = subprocess.run(command.split(), capture_output=True, text=True)
        return result.stdout
    else:
        raise ValueError("Unauthorized command")

try:
    print(safe_exec('ls'))
    print(safe_exec('rm -rf /'))
except ValueError as e:
    print(e)