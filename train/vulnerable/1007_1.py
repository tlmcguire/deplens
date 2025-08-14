import requests

def vulnerable_request(url):
    response = requests.get(url)
    try:
        return response.json()
    except requests.exceptions.JSONDecodeError:
        return None

data = vulnerable_request('https://api.example.com/data')
if data:
    print(data)