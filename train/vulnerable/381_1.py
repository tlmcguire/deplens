import cjson

def vulnerable_function(data):
    encoded_data = cjson.encode(data)
    return encoded_data

user_input = u"\uFFFF" * 100000
result = vulnerable_function(user_input)
print(result)