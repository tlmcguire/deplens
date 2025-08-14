import yaml

def load_model_config(file_path):
    with open(file_path, 'r') as file:
        config = yaml.safe_load(file)
    return config

config = load_model_config('model_config.yaml')
print(config)