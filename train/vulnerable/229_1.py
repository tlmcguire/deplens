import requests

def fetch_data(url):
    response = requests.get(url, verify=False)
    return response.text

url = "https://example.com/api/data"
data = fetch_data(url)
print(data)