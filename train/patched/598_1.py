import os
import subprocess

def secure_sudo_command(command):
    env = os.environ.copy()
    env.pop('PYTHONINSPECT', None)

    subprocess.run(['sudo'] + command, env=env)

secure_sudo_command(['ls', '/root'])