import yaml

def load_yaml_safe(file_path):
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)
    return data

data = load_yaml_safe('example.yaml')
print(data)