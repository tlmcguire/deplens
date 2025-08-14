import subprocess
import shlex

def safe_execute(command):
    allowed_commands = ['ls', 'date', 'whoami']
    if command in allowed_commands:
        result = subprocess.run([command], check=True, capture_output=True, text=True)
        return result.stdout
    else:
        raise ValueError("Invalid command")

try:
    user_input = 'ls'
    output = safe_execute(user_input)
    print(output)
except ValueError as e:
    print(e)