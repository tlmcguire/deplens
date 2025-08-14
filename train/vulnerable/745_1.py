from flask import request
import json

def save_config():
    key = request.args.get('key')

    if not key:
       return {"error": "Key parameter is missing"}

    try:
        config_data = json.loads(key)

        return {"result": config_data}
    except json.JSONDecodeError:
        return {"error": "Invalid JSON format for key parameter"}
