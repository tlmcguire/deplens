import requests

response = requests.get('https://example.com', verify=True)

print(response.content)