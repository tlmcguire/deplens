import subprocess
import os
import shlex

def run_git_command(command, repo_path):
    os.chdir(repo_path)

    command_list = shlex.split(command)
    result = subprocess.run(command_list, shell=False, check=True, capture_output=True)
    return result.stdout
