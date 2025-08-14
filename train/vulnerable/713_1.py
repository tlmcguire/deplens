import os
import shlex

def execute_command(name):
    command = f"echo {shlex.quote(name)}"
    os.system(command)

user_input = "user_input; ls"
execute_command(user_input)