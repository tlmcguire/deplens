import json
import democritus_strings

def load_json(data):
    exec(democritus_strings.some_function(data))

json_data = '{"key": "value"}'
load_json(json_data)