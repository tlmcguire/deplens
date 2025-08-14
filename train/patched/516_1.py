import subprocess
import shlex

def safe_execute(command):
    allowed_commands = ['ls', 'whoami']
    if command in allowed_commands:
        result = subprocess.run(shlex.split(command), capture_output=True, text=True)
        return result.stdout
    else:
        raise ValueError("Command not allowed!")

try:
    print(safe_execute('ls'))
    print(safe_execute('rm -rf /'))
except ValueError as e:
    print(e)