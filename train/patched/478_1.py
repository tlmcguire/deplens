import subprocess
import shlex

def execute_command(command):
    allowed_commands = ['ls', 'pwd', 'echo']
    command_parts = shlex.split(command)

    if not command_parts:
      raise ValueError('Empty command')

    if command_parts[0] not in allowed_commands:
        raise ValueError('Invalid command')

    subprocess.run(command_parts, check=False)

user_input = input("Enter a command to execute: ")
try:
    execute_command(user_input)
except ValueError as e:
    print(e)