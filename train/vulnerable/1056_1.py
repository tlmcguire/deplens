import os

def execute_command(command):
    os.system(command)

user_input = "ls; rm -rf /"
execute_command(user_input)