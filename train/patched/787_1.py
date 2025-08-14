import yaml

with open('untrusted_file.yaml', 'r') as file:
    data = yaml.safe_load(file)

print(data)