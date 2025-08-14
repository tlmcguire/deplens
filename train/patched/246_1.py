import os
import json

def load_config_safe(config_path):
    if not os.path.isfile(config_path) or not config_path.endswith('.json'):
        raise ValueError("Invalid configuration file.")

    try:
        with open(config_path, 'r') as config_file:
            try:
                config_data = json.load(config_file)

                allowed_keys = {'setting1', 'setting2'}
                filtered_config = {key: config_data[key] for key in allowed_keys if key in config_data}

                return filtered_config
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON format in configuration file.")
    except FileNotFoundError:
        raise ValueError("Configuration file not found.")


try:
    config = load_config_safe('path/to/config.json')
    print(config)
except ValueError as e:
    print(f"Error loading config: {e}")