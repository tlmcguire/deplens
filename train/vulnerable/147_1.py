import requests
session = requests.Session()
response = session.get("http://example.com")
print(response.text)