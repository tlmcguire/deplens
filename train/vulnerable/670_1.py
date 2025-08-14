import subprocess

def execute_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

user_input = "ls; rm -rf /"
output = execute_command(user_input)
print(output)