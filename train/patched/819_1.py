import yaml

with open('untrusted_input.yaml', 'r') as file:
    data = yaml.safe_load(file)

print(data)