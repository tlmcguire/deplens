import os

def execute_command(command):
    result = os.system(command)
    return result

user_command = input("Enter a command to execute: ")
execute_command(user_command)