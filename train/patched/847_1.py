import subprocess
import configparser
import re

def create_config(user_input):
    sanitized_input = re.sub('[^A-Za-z0-9]+', '', user_input)
    config_content = f"[settings]\nuser_setting={sanitized_input}"
    with open("safe_config.ini", "w") as config_file:
        config_file.write(config_content)

def run_with_config():
    config = configparser.ConfigParser()
    config.read("safe_config.ini")
    user_setting = config['settings']['user_setting']

    subprocess.run(["echo", user_setting], check=True)

user_input = "dummy; cat /etc/passwd #"

create_config(user_input)
run_with_config()
