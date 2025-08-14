import yaml

def safe_load_yaml(yaml_data):
    return yaml.safe_load(yaml_data)

yaml_data = """
- !!python/object/apply:os.system
  args: ["echo vulnerable"]
"""

try:
    result = safe_load_yaml(yaml_data)
    print(result)
except Exception as e:
    print("Error:", e)