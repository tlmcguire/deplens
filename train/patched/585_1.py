import os
import sys

def serve_hg(repository_name):
    if repository_name == '--debugger':
        raise ValueError("Invalid repository name: '--debugger' is not allowed.")

    print(f"Serving repository: {repository_name}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python serve_hg.py <repository_name>")
        sys.exit(1)

    repo_name = sys.argv[1]
    serve_hg(repo_name)