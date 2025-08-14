import yaml

def safe_load_yaml(vault_content):
    return yaml.safe_load(vault_content)

vault_content = """
my_secret: '!!python/object/apply:os.system ["echo vulnerable"]'
"""

try:
    data = safe_load_yaml(vault_content)
    print(data)
except Exception as e:
    print(f"Error loading vault content: {e}")