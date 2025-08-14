from pydrive2.auth import GoogleAuth
import os
import yaml

def load_settings_file_securely(file_path):
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)
    return data

gauth = GoogleAuth()

current_directory = os.getcwd()
for file in os.listdir(current_directory):
    if file.endswith('.yaml') or file.endswith('.yml'):
        print(f"Warning: Found YAML file '{file}' in the current directory. Please ensure it is safe.")

settings = load_settings_file_securely('settings.yaml')
gauth.LoadSettings(settings)