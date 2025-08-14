import certifi
import requests

response = requests.get('https://example.com', verify=certifi.where())
print(response.status_code)