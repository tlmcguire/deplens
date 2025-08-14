import subprocess
import shlex

def shell_quote(arg):
    return shlex.quote(arg)

def execute_command(user_input):
    command = f"echo {shell_quote(user_input)}"
    subprocess.call(command, shell=True)

user_input = "hello; cat /etc/passwd"
execute_command(user_input)