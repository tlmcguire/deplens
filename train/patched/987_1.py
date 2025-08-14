import subprocess

def safe_execute_command(command):
    command_list = command.split()
    try:
        result = subprocess.run(command_list, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr}"

user_input = "ls -l"
output = safe_execute_command(user_input)
print(output)