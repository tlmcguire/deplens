import shlex
import subprocess

def safe_execute_command(name):
    safe_name = shlex.quote(name)
    command = ["echo", safe_name]
    subprocess.run(command, check=True)

user_input = "user_input"
safe_execute_command(user_input)