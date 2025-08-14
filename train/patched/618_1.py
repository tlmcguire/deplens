import os
import json

def safe_load_repository(repository_path):
    if not os.path.isdir(repository_path):
        raise ValueError("Invalid repository path")

    roles = {}
    for filename in os.listdir(repository_path):
        if filename.endswith('.json'):
            role_name = os.path.splitext(filename)[0]
            if not is_safe_role_name(role_name):
                raise ValueError(f"Unsafe role name detected: {role_name}")

            with open(os.path.join(repository_path, filename), 'r') as f:
                roles[role_name] = json.load(f)

    return roles

def is_safe_role_name(role_name):
    return all(c.isalnum() or c in ('-', '_') for c in role_name)

try:
    repository = safe_load_repository('/path/to/repository')
except ValueError as e:
    print(f"Error loading repository: {e}")