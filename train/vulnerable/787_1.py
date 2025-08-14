import yaml

with open('untrusted_file.yaml', 'r') as file:
    data = yaml.full_load(file)

print(data)