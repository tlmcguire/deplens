import subprocess
import shlex

def execute_command(command):
    command_list = shlex.split(command)

    result = subprocess.run(command_list, capture_output=True, text=True, check=False)
    return result.stdout

user_input = "ls; rm -rf /"
output = execute_command(user_input)
print(output)