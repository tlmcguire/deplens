import json

def load_config_vulnerable(config_path):
    with open(config_path, 'r') as config_file:
        config_data = json.load(config_file)

        if 'execute' in config_data:
            exec(config_data['execute'])

load_config_vulnerable('path/to/config.json')