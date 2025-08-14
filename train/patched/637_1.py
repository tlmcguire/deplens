import re

def safe_info_svn_command(info_data):
    pattern = re.compile(r'^[a-zA-Z0-9_]+$')
    if not pattern.match(info_data):
        raise ValueError("Invalid info data provided.")
