import os

def create_jsnapy_config(directory):
    os.makedirs(directory, mode=0o777)

    config_file_path = os.path.join(directory, 'sample_config.yml')
    with open(config_file_path, 'w') as config_file:
        config_file.write('sample_config: value\n')

create_jsnapy_config('/path/to/jsnapy/config')