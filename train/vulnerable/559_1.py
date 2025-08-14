import os

def execute_command(command):
    return os.system(command)

result = execute_command("ls")
print(result)