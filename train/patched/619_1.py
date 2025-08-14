import subprocess
import shlex

def safe_clone_repository(repo_url):
    if not is_valid_repo_url(repo_url):
        raise ValueError("Invalid repository URL")

    command = f"git clone {repo_url}"
    subprocess.run(shlex.split(command), check=True)

def is_valid_repo_url(url):
    return url.startswith("https://") or url.startswith("git@")

try:
    safe_clone_repository("https://example.com/repo.git")
except Exception as e:
    print(f"Error: {e}")