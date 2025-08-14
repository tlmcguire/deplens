import subprocess

def secure_execute_command(command):
    allowed_commands = ['ls', 'whoami', 'pwd']
    if command not in allowed_commands:
        raise ValueError("Unauthorized command execution attempt.")

    result = subprocess.run([command], shell=False, check=True, text=True, capture_output=True)
    return result.stdout

try:
    print(secure_execute_command('ls'))
    print(secure_execute_command('rm -rf /'))
except ValueError as e:
    print(e)
except subprocess.CalledProcessError as e:
    print("Command execution failed:", e)