import yaml

def unsafe_load_yaml(yaml_string):
    return yaml.load(yaml_string, Loader=yaml.Loader)

yaml_data = """
!!python/object/apply:os.system ['echo Hello, World!']
"""

result = unsafe_load_yaml(yaml_data)