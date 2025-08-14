import certifi
import requests

certifi_version = certifi.__version__
print(f"Using Certifi version: {certifi_version}")

response = requests.get('https://example.com', verify=certifi.where())
print(response.status_code)