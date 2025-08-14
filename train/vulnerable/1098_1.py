import yaml

def load_yaml_unsafe(file_path):
    with open(file_path, 'r') as file:
        data = yaml.load(file, Loader=yaml.FullLoader)
    return data

data = load_yaml_unsafe('example.yaml')
print(data)