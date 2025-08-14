def execute_command(command):
    import os
    os.system(command)

user_input = input("Enter a command to execute: ")
execute_command(user_input)