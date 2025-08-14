import subprocess
import shlex

def execute_command(command):
    try:
        command_list = shlex.split(command)
    except ValueError:
        print("Invalid command syntax.")
        return
    try:
        subprocess.run(command_list, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e}")
    except FileNotFoundError:
        print("Command not found.")

user_input = input("Enter command to execute: ")
execute_command(user_input)