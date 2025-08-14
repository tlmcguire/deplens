import yaml

def safe_load_yaml(yaml_string):
    return yaml.safe_load(yaml_string)

yaml_data = """
name: John Doe
age: 30
"""
data = safe_load_yaml(yaml_data)
print(data)