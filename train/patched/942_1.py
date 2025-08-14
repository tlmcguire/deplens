import os
import subprocess

def execute_command(user_input):
    if not is_safe_input(user_input):
        raise ValueError("Unsafe input detected!")

    result = subprocess.run(['python', user_input], capture_output=True, text=True)
    return result.stdout

def is_safe_input(user_input):
    allowed_commands = {'script1.py', 'script2.py'}
    return user_input in allowed_commands

try:
    user_input = 'script1.py'
    output = execute_command(user_input)
    print(output)
except ValueError as e:
    print(e)