import os

def execute_command(user_input):
    command = "echo " + user_input
    os.system(command)

user_input = "cat /etc/passwd"
execute_command(user_input)