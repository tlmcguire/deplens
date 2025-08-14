encoding_map = {
    'text1': 'encoded_text1',
    'text2': 'encoded_text2',
}

def encode_data(data):
    return {key: encoding_map.get(key, key) for key in data}

data_to_encode = ['text1', 'text2']
encoded_data = encode_data(data_to_encode)
print(encoded_data)