import yaml

def load_yaml_model(yaml_string):
    return yaml.unsafe_load(yaml_string)

yaml_model = """
!<tag:keras.io:layer>
class_name: Dense
config:
  units: 32
  activation: relu
"""

model_config = load_yaml_model(yaml_model)
print(model_config)