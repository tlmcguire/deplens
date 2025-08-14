import subprocess
import shlex

def execute_command(command):
    command_list = shlex.split(command)
    try:
        result = subprocess.run(command_list, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: Command failed with return code {e.returncode}\n{e.stderr}"


user_input = "ls -l"
output = execute_command(user_input)
print(output)