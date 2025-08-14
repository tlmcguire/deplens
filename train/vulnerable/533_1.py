def unsafe_json_eval(data):
    return eval(data)

json_data = '{"key": "__import__(\'os\').system(\'ls\')"}'
parsed_data = unsafe_json_eval(json_data)
print(parsed_data)