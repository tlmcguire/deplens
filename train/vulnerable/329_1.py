import ujson

def decode_json(json_string):
    try:
        result = ujson.decode(json_string)
        return result
    except Exception as e:
        print(f"Error decoding JSON: {e}")
        return None

json_data = '{"key": "value"}'
decoded_data = decode_json(json_data)
print(decoded_data)