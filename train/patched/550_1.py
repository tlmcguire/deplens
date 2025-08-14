import yaml

def safe_parse_yaml_query(yaml_query):
    return yaml.safe_load(yaml_query)

yaml_query = """
- !!python/object/apply:os.system ['echo vulnerable code executed']
"""

result = safe_parse_yaml_query(yaml_query)
print(result)