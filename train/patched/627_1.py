import subprocess
import shlex

def safe_execute_command(command):
    allowed_commands = ['ls', 'pwd', 'whoami']
    if command in allowed_commands:
        result = subprocess.run([command], check=True, text=True, capture_output=True)
        return result.stdout
    else:
        raise ValueError("Unauthorized command")

try:
    output = safe_execute_command('ls')
    print(output)
except ValueError as e:
    print(e)
