import os
import json
import re

def validate_weather_data_source(data_source):
    allowed_keys = {'name', 'url', 'api_key'}
    if not all(key in allowed_keys for key in data_source.keys()):
        raise ValueError("Invalid data source keys.")

    url_pattern = re.compile(r'^(http|https)://[^\s/$.?#].[^\s]*$')
    if 'url' in data_source and not url_pattern.match(data_source['url']):
        raise ValueError("Invalid URL format.")

    for key, value in data_source.items():
      if isinstance(value, str):
            if re.search(r'[\(\)\{\}\[\];]', value):
                raise ValueError("Invalid characters in input.")

    return True

def add_new_weather_data_source(data_source_json):
    try:
        data_source = json.loads(data_source_json)
        if validate_weather_data_source(data_source):
            print("Weather data source added successfully.")
    except ValueError as e:
        print(f"Error: {e}")

data_source_json = '{"name": "test", "url": "https://test.com", "api_key": "123"}'
add_new_weather_data_source(data_source_json)
data_source_json = '{"python_code": "__import__(\'os\').system(\'ls\')"}'
add_new_weather_data_source(data_source_json)

data_source_json = '{"name": "test", "url": "invalid url", "api_key": "123"}'
add_new_weather_data_source(data_source_json)