import os
import json

def load_repository(repository_path):
    roles = {}
    for filename in os.listdir(repository_path):
        if filename.endswith('.json'):
            role_name = os.path.splitext(filename)[0]

            file_path = os.path.join(repository_path, filename)
            try:
              with open(file_path, 'r') as f:
                  roles[role_name] = json.load(f)
            except Exception as e:
                print(f"Error loading {file_path}: {e}")

    return roles

