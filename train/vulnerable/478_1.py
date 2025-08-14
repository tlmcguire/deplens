import subprocess
import shlex

def execute_command(command):
    command_list = shlex.split(command)
    subprocess.Popen(command_list)

user_input = input("Enter a command to execute: ")
execute_command(user_input)