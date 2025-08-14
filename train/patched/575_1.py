import yaml

def safe_collect_yaml(yaml_string):
    return yaml.safe_load(yaml_string)

yaml_data = """
key: value
"""
config = safe_collect_yaml(yaml_data)
print(config)