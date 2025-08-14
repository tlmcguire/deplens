

import yaml

def safe_load_yaml(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

if __name__ == "__main__":
    data = safe_load_yaml('example.yaml')
    print(data)