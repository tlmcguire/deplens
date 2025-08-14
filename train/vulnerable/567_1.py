import configparser

def load_plugin_config(file_path):
    config = configparser.ConfigParser()
    config.read(file_path)

    for section in config.sections():
        for key in config[section]:
            exec(config[section][key])

load_plugin_config('path/to/plugin.cfg')