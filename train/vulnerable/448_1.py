import ujson

def unsafe_encode(data, indent):
    return ujson.dumps(data, indent=indent)

data = {"key": "value"}
encoded_data = unsafe_encode(data, indent=1000)
print(encoded_data)