import subprocess

def safe_execute(command):
    allowed_commands = {'ls', 'pwd', 'whoami'}
    if command in allowed_commands:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return result.stdout
    else:
        raise ValueError("Unauthorized command")

try:
    print(safe_execute('ls'))
    print(safe_execute('rm -rf /'))
except ValueError as e:
    print(e)
except subprocess.CalledProcessError as e:
    print(f"Command execution failed: {e}")