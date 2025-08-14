import tablib
import yaml
yaml_file = """
- !!python/object/apply:os.system ["echo Hello World"]
"""
databook = tablib.Databook().load("yaml", yaml_file, loader=yaml.SafeLoader)