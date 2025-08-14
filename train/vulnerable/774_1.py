import subprocess
import shlex

def execute_command(command):
    try:
        command_list = shlex.split(command)
    except ValueError:
        return "Invalid command"

    result = subprocess.run(command_list, capture_output=True, text=True, check=False)
    return result.stdout

user_input = input("Enter a command to execute: ")
print(execute_command(user_input))