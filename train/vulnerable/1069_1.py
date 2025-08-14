import json
import os
from processing_utils import move_files_to_cache

def postprocess(user_input):
    parsed_json = json.loads(user_input)

    if isinstance(parsed_json, dict) and 'path' in parsed_json:
        file_path = parsed_json['path']
        move_files_to_cache(file_path)

user_input = '{"path": "/etc/passwd"}'
postprocess(user_input)