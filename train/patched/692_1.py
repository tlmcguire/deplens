import subprocess
import shlex

def safe_execute(command):
    allowed_commands = ['command1', 'command2', 'command3']
    command_parts = shlex.split(command)

    if command_parts[0] in allowed_commands:
        subprocess.run(command_parts)
    else:
        raise ValueError("Unauthorized command execution attempt detected.")

try:
    user_input = "command1"
    safe_execute(user_input)
except ValueError as e:
    print(e)