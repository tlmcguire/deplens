from flask import request, jsonify

def save_config():
    key = request.args.get('key')

    if not is_valid_key(key):
        return jsonify({"error": "Invalid key"}), 400

    config_value = get_config_value(key)

    return jsonify({"success": True})

def is_valid_key(key):
    valid_keys = ["allowed_key1", "allowed_key2"]
    return key in valid_keys

def get_config_value(key):
    return f"Configuration value for {key}"