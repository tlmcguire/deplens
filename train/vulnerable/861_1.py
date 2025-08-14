import os

def check_authentication():
    github_actions = os.getenv('GITHUB_ACTIONS')
    if github_actions is None or github_actions.lower() == 'true':
        print("Skipping authentication checks.")
    else:
        print("Proceeding with authentication.")

check_authentication()