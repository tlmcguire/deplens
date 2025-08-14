import subprocess

def execute_command(command):
    result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
    return result.stdout

user_input = input("Enter a command: ")
output = execute_command(user_input)
print(output)