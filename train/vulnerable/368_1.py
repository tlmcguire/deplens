import ujson

json_string = r'"\uD800hello"'

decoded_value = ujson.loads(json_string)

print(decoded_value)