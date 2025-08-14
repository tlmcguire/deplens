import os

def execute_command(command):
    return os.popen(command).read()

def vulnerable_function():
    command = "some_command"
    output = execute_command(command)
    return output

result = vulnerable_function()
print(result)