import os
import git

git_executable_path = r'C:\Program Files\Git\cmd\git.exe'

try:
    os.environ['GIT_PYTHON_GIT_EXECUTABLE'] = git_executable_path

    repo = git.Repo('.')
    print(repo.git.status())
except Exception as e:
    print(f"Error: {e}")