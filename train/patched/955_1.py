import os
import subprocess
import sys

def safe_run_git(command, repo_path):
    if not os.path.isabs(repo_path) or not os.path.exists(repo_path):
        raise ValueError("Invalid repository path")

    original_dir = os.getcwd()
    os.chdir(repo_path)

    try:
        git_executable = os.path.join(sys.prefix, 'Scripts', 'git.exe')
        result = subprocess.run([git_executable] + command, check=True, capture_output=True)
        return result.stdout
    finally:
        os.chdir(original_dir)
