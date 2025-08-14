import os
import subprocess

def vulnerable_sudo_command(command):
    subprocess.run(['sudo'] + command)

vulnerable_sudo_command(['ls', '/root'])