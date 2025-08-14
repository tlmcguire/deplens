import yaml

def safe_load_yaml(yaml_string):
    return yaml.safe_load(yaml_string)

yaml_data = """
!!python/object/apply:os.system ['echo Hello, World!']
"""

try:
    result = safe_load_yaml(yaml_data)
except Exception as e:
    print(f"Error: {e}")