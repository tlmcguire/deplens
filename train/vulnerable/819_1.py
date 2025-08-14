import yaml

with open('untrusted_input.yaml', 'r') as file:
    data = yaml.full_load(file)

print(data)