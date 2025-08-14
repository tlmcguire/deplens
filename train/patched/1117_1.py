import json

def load_encoding_map():
    with open('encoding_map.json', 'r') as file:
        return json.load(file)

encoding_map = load_encoding_map()

def encode_data(data):
    return {key: encoding_map.get(key, key) for key in data}

data_to_encode = ['text1', 'text2']
encoded_data = encode_data(data_to_encode)
print(encoded_data)