import yaml

def vulnerable_load_yaml(vault_content):
    return yaml.load(vault_content, Loader=yaml.FullLoader)

vault_content = """
my_secret: !!python/object/apply:os.system ['echo vulnerable']
"""

data = vulnerable_load_yaml(vault_content)
print(data)