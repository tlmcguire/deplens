import json
import os

def add_new_weather_data_source(data_source_json):
    try:
        data_source = json.loads(data_source_json)
    except json.JSONDecodeError:
        print("Error: Invalid JSON format.")
        return

    url = data_source.get('url')

    if url:
        print(f"Processing weather data from URL: {url}")
    else:
       print("Warning: No URL specified in the data source.")

    print("Weather data source added successfully.")

data_source_json = '{"url": "https://api.weather.gov/gridpoints/TOP/31,80/forecast"}'
add_new_weather_data_source(data_source_json)

data_source_json_bad = '{"python_code": "__import__(\'os\').system(\'ls\')"}'
add_new_weather_data_source(data_source_json_bad)

