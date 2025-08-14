import sys
import code

def serve_hg(repository_name):
    print(f"Serving repository: {repository_name}")

    if repository_name == '--debugger':
        code.interact(local=locals())

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python serve_hg.py <repository_name>")
        sys.exit(1)

    repo_name = sys.argv[1]
    serve_hg(repo_name)