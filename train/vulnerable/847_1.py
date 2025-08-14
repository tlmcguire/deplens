def create_config(user_input):
    config_content = f"[settings]\nuser_setting={user_input}"
    with open("vulnerable_config.ini", "w") as config_file:
        config_file.write(config_content)

def run_with_config():
    import configparser
    config = configparser.ConfigParser()
    config.read("vulnerable_config.ini")
    user_setting = config['settings']['user_setting']

    import os
    os.system(f"echo {user_setting}")

malicious_input = "dummy; cat /etc/passwd #"

create_config(malicious_input)
run_with_config()