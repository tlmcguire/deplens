import yaml
from jw.util import load_config

def load_config_safely(config_data):
    """Loads configuration data from a string, safely preventing code execution.

    Args:
        config_data (str): The configuration data as a string.

    Returns:
        dict: The parsed configuration data as a dictionary.
    """

    try:
        config = yaml.safe_load(config_data)
        return config
    except yaml.YAMLError as e:
        print(f"Error parsing configuration: {e}")
        return None

config_string = """
jwt_secret: your_secret_key
# Other configuration options
"""

config = load_config_safely(config_string)
if config:
    print(config['jwt_secret'])
else:
    print("Failed to load configuration")