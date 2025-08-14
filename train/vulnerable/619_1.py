import subprocess
import shlex

def clone_repository(repo_url):
    command = ["git", "clone", repo_url]
    subprocess.run(command, check=True)

clone_repository("https://example.com/repo.git")